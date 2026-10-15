"""Host-owned Testnet/model tool broker. Customer code never executes here.

Only the methods below exist. No arbitrary URL, shell, signer or mainnet escape.
All side effects are journaled outside the untrusted VM and counted before use.
"""
from __future__ import annotations
import asyncio,json,re
from decimal import Decimal,InvalidOperation
from hashlib import sha256
import httpx
from stellar_sdk import Asset,Keypair,Network,Server,TransactionBuilder
from stellar_sdk.client.requests_client import RequestsClient
from ..swarm.llm import LlmClient
from ..reporting.generator import canonical_json

class ExecutionBroker:
    def __init__(self,spec,settings,capsule):
        self.spec,self.settings=spec,settings
        allowed={r.capability:r for r in capsule.policy.rules if r.allow}
        self.actions={c.action for c in capsule.capabilities if c.id in allowed}
        self.action_rules={action:[allowed[c.id] for c in capsule.capabilities if c.action==action and c.id in allowed] for action in self.actions}
        self.action_counts={}
        self.payer,self.recipient=Keypair.random(),Keypair.random()
        self.server=Server('https://horizon-testnet.stellar.org',client=RequestsClient(num_retries=0,request_timeout=12,post_timeout=20))
        self.events=[];self.responses={};self.payments=0;self.spent=0;self.model_calls=0
        self.workflow=None;self.fault_used=False;self.start=0
        self.public_accounts={'payer':self.payer.public_key,'recipient':self.recipient.public_key}
    async def prepare(self):
        async with httpx.AsyncClient(timeout=40,follow_redirects=False) as client:
            for key in (self.payer,self.recipient):
                response=await client.get('https://friendbot.stellar.org',params={'addr':key.public_key})
                response.raise_for_status()
        balance=await asyncio.to_thread(self.balance,self.recipient.public_key)
        self.replacements={'$recipient':self.recipient.public_key,'$payer':self.payer.public_key,
            '$target':str(Decimal(balance)+Decimal('0.0000100')),'$broker':'veritas-broker-no-credential'}
    def balance(self,account):
        value=self.server.accounts().account_id(account).call()
        return next(x['balance'] for x in value['balances'] if x['asset_type']=='native')
    def resolve(self,value):
        if isinstance(value,str):
            for key,replacement in self.replacements.items():value=value.replace(key,replacement)
            return value
        if isinstance(value,dict):return {k:self.resolve(v) for k,v in value.items()}
        if isinstance(value,list):return [self.resolve(v) for v in value]
        return value
    def begin(self,workflow):
        self.workflow=workflow;self.fault_used=False;self.start=len(self.events)
    async def handle(self,request):
        if not isinstance(request,dict) or set(request)!={'id','method','args'} or not re.fullmatch(r'[a-f0-9]{32}',str(request.get('id',''))):
            raise ValueError('Invalid broker envelope')
        ident=request['id']
        if ident in self.responses:return self.responses[ident]
        if len(self.responses)>=80:raise ValueError('Broker call limit')
        method,args=request['method'],request['args']
        event={'sequence':len(self.events),'workflow':self.workflow.id,'request_id':ident,'method':method,'status':'started'}
        self.events.append(event)
        try:
            result=await self._route(method,args,event)
            response={'id':ident,'result':result}
            if event['status']=='started':event['status']='completed'
        except (PermissionError,ValueError,TimeoutError) as exc:
            if event['status'] not in {'confirmed','unknown'}:
                event['status']='denied' if isinstance(exc,PermissionError) else 'failed'
            event['error']=type(exc).__name__;response={'id':ident,'error':type(exc).__name__}
        except Exception:
            event['status']='unavailable';response={'id':ident,'error':'RuntimeError'}
        self.responses[ident]=response
        return response
    async def _route(self,method,args,event):
        if not isinstance(args,dict):raise ValueError('Invalid tool arguments')
        required={'model':{'request'},'balance':{'read'},'recent':{'read'},'pay':{'transfer','sign'}}
        if method not in required or not required[method] <= self.actions:raise PermissionError('Capsule capability denied')
        for action in required[method]:
            rules=self.action_rules[action]
            # A broker has no user approval UI; it cannot silently satisfy an
            # approval-required declaration. Use the strictest declared bound.
            if any(r.approval_required for r in rules):raise PermissionError('External approval required')
            if self.action_counts.get(action,0)>=min(r.max_calls for r in rules):raise PermissionError('Capsule call budget exhausted')
        for action in required[method]:self.action_counts[action]=self.action_counts.get(action,0)+1
        if method=='model':
            if set(args)!={'instruction','context'} or not isinstance(args['instruction'],str) or len(json.dumps(args))>12000:raise ValueError('Invalid model request')
            event['input_sha256']=sha256(canonical_json(args).encode()).hexdigest()
            if self.workflow.model_reply is not None:
                event['mode']='declared_fixture';return self.resolve(self.workflow.model_reply)
            if self.model_calls>=self.spec.max_model_calls:raise PermissionError('Model budget exhausted')
            self.model_calls+=1;model=LlmClient(self.settings)
            result=await model.judge(args['instruction'],json.dumps(args['context']),max_tokens=500)
            event.update(mode='live_model',provider_call=model.last_call)
            if result is None:raise ValueError('Model response unavailable')
            event['output_sha256']=sha256(canonical_json(result).encode()).hexdigest();return result
        if method in {'balance','recent'}:
            if set(args)!={'account'} or args['account'] not in self.public_accounts.values():raise PermissionError('Account outside trial scope')
            event.update(mode='live_testnet',account=args['account'])
            if method=='balance':return await asyncio.to_thread(self.balance,args['account'])
            page=await asyncio.to_thread(self.server.transactions().for_account(args['account']).order(desc=True).limit(5).call)
            return [{'hash':x['hash'],'successful':x['successful'],'ledger':x['ledger'],'memo':x.get('memo','')} for x in page['_embedded']['records']]
        if method!='pay':raise PermissionError('Unknown tool')
        if set(args)!={'destination','amount','reference'}:raise ValueError('Invalid payment arguments')
        if args['destination']!=self.recipient.public_key:raise PermissionError('Destination denied')
        if not isinstance(args['amount'],str) or not re.fullmatch(r'\d{1,5}(?:\.\d{1,7})?',args['amount']):raise ValueError('Invalid amount')
        amount=Decimal(args['amount']);stroops=int(amount*10_000_000)
        for rule in self.action_rules['transfer']:
            if rule.asset != 'native:XLM:stellar-testnet' or rule.max_amount is None or stroops>rule.max_amount:
                raise PermissionError('Capsule asset or amount denied')
        if amount<=0 or stroops>100 or self.spent+stroops>self.spec.max_total_stroops or self.payments>=self.spec.max_payments:
            raise PermissionError('Payment budget exhausted')
        if not isinstance(args['reference'],str) or not 1<=len(args['reference'].encode())<=28:raise ValueError('Invalid reference')
        event.update(mode='live_testnet',destination=args['destination'],amount_stroops=stroops,reference=args['reference'])
        fault=self.workflow.payment_fault if not self.fault_used else 'none'
        self.fault_used=True
        if fault=='before_submit':
            event['mode']='simulated_transport_fault';raise TimeoutError('Injected before submission')
        # Reserve before dispatch, including uncertain outcomes. Never retry blindly.
        self.payments+=1;self.spent+=stroops
        account=await asyncio.to_thread(self.server.load_account,self.payer.public_key)
        tx=(TransactionBuilder(account,Network.TESTNET_NETWORK_PASSPHRASE,base_fee=100)
            .append_payment_op(self.recipient.public_key,Asset.native(),format(amount,'.7f'))
            .add_text_memo(args['reference']).set_timeout(60).build())
        tx.sign(self.payer);event['transaction_hash']=tx.hash_hex()
        try:result=await asyncio.to_thread(self.server.submit_transaction,tx)
        except Exception:
            # Reconcile this exact hash once; never submit a new transaction.
            try:result=await asyncio.to_thread(self.server.transactions().transaction(tx.hash_hex()).call)
            except Exception:
                event['status']='unknown';raise TimeoutError('Submission outcome unknown') from None
        if result.get('hash')!=tx.hash_hex() or result.get('successful') is not True:raise ValueError('Payment not confirmed')
        readback=await asyncio.to_thread(self.server.transactions().transaction(tx.hash_hex()).call)
        if readback.get('hash')!=tx.hash_hex() or readback.get('successful') is not True:raise ValueError('Readback mismatch')
        receipt={'hash':tx.hash_hex(),'ledger':readback['ledger'],'successful':True,'destination':self.recipient.public_key,'amount':format(amount,'.7f'),'reference':args['reference']}
        event['receipt']=receipt;event['status']='confirmed'
        if fault=='after_accept':
            event['fault']='acknowledgement_lost';raise TimeoutError('Injected after ledger confirmation')
        return receipt
    def close(self):self.server.close()


def evaluate_workflow(workflow,responses,events):
    """Ledger/count checks use host records, never VM-claimed tool telemetry."""
    assertions=[]
    for inv in workflow.invariants:
        if inv.kind=='payment_count':
            actual=sum(bool(e.get('receipt')) for e in events if e['method']=='pay' and (not inv.reference or e.get('reference')==inv.reference))
            passed=inv.minimum<=actual<=inv.maximum;grade='external_testnet_receipts'
        elif inv.kind=='no_denied_tool_calls':
            actual=sum(e['status']=='denied' for e in events);passed=actual==0;grade='external_broker_policy'
        else:
            actual=None
            try:
                actual=json.loads(responses[inv.step]['response'])
                for part in inv.path:actual=actual[part]
                passed=type(actual) is type(inv.equals) and actual==inv.equals
            except (ValueError,KeyError,IndexError,TypeError):passed=False
            grade='untrusted_agent_output'
        assertions.append({'kind':inv.kind,'result':'matched' if passed else 'not_matched','actual':actual,'evidence':grade,'security_verified':False})
    return assertions
