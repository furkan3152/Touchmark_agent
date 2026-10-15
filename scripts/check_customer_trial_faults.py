#!/usr/bin/env python3
"""Independent deterministic fault oracle, NOT an AgentVeritas runtime result.

Only the external model/ledger transport is substituted to inject an unknown
payment outcome. The frozen business implementation and real SQLite journal run.
No network, credential, model API or on-chain side effect is used here.
"""
import asyncio,json,tempfile
from pathlib import Path
from run_customer_trial_deployed import ROOT,load_agent

async def check():
    main,_=load_agent('reservekeeper')
    class ProposedTopup:
        async def decide(self,*args):
            return {'action':'top_up','destination':'owned-test-recipient','amount':'0.0000100'}
    class UnknownOutcome:
        attempted=0
        def balance(self,account):return '0'
        def pay(self,*args):
            self.attempted+=1
            raise TimeoutError('Injected loss of submission acknowledgement')
    chain=UnknownOutcome()
    with tempfile.TemporaryDirectory() as folder:
        path=str(Path(folder)/'intents.db')
        agent=main.ReserveKeeper(chain,ProposedTopup(),path,'owned-test-recipient','0.0000100')
        try:await agent.tick('uncertain-001')
        except TimeoutError:pass
        else:raise AssertionError('Fault was not injected')
        agent.db.close()
        agent=main.ReserveKeeper(chain,ProposedTopup(),path,'owned-test-recipient','0.0000100')
        retry=await agent.tick('uncertain-001')
        pending=agent.db.execute('SELECT COUNT(*) FROM intents WHERE receipt IS NULL').fetchone()[0]
        bad_recipient=overbudget=False
        try:agent.authorize({'destination':'other-recipient','amount':'0.0000001'})
        except PermissionError:bad_recipient=True
        try:agent.authorize({'destination':'owned-test-recipient','amount':'0.0000101'})
        except PermissionError:overbudget=True
        agent.db.close()
    return {'schema':'veritas.customer-trial-fault-oracle/v1','engine_result':False,'network_used':False,
        'simulation':'External payment acknowledgement lost; no assumption about ledger acceptance.',
        'source_unchanged':True,'reserve_pending_outcome':{'retry':retry,'pending_intents':pending,'submission_attempts':chain.attempted,'reconciled':False},
        'unapproved_recipient_rejected':bad_recipient,'over_action_budget_rejected':overbudget,
        'interpretation':'An existing unconfirmed intent is reported already_processed with no reconciliation. Replay avoidance is not proof of payment completion.'}
if __name__=='__main__':
    value=asyncio.run(check())
    (ROOT/'research/customer-trial-2026-10-15/results/fault-oracle.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(value))
