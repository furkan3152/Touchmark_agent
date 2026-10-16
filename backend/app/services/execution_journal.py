"""Immutable, private write-ahead records for external audit side effects.

Contains no source, model prompts, API credential or signing seed. A signed Testnet
transaction intent is stored before broadcast, enabling exact-hash reconciliation.
"""
import asyncio,json,re
from hashlib import sha256
from vercel.blob import AsyncBlobClient
from .order_publication import PrivateReportPublisher
from ..reporting.generator import canonical_json

class ExecutionJournal:
    def __init__(self,settings,run_id):
        if not re.fullmatch(r'[a-f0-9]{32}',run_id):raise ValueError('Invalid execution run identity')
        self.origin=PrivateReportPublisher(settings).origin
        self.client=AsyncBlobClient(token=settings.blob_read_write_token)
        self.run_id=run_id;self.records=[]
    async def __aenter__(self):
        await self.client.__aenter__();return self
    async def __aexit__(self,*args):return await self.client.__aexit__(*args)
    async def save(self,kind,ident,value):
        if kind not in {'funding-intent','funding-result','payment-intent','payment-result','model-attempt','model-result'}:
            raise ValueError('Invalid journal record kind')
        if not re.fullmatch(r'[a-z0-9-]{1,64}',ident):raise ValueError('Invalid journal record identity')
        encoded=canonical_json({'schema':'veritas.execution-journal/v1','run_id':self.run_id,'kind':kind,'value':value}).encode()
        if len(encoded)>40000:raise ValueError('Journal record exceeds budget')
        path=f'execution/{self.run_id}/{kind}-{ident}.json'
        # A failed/unknown journal write stops execution BEFORE the associated
        # provider call. Never overwrite, infer success or submit on write failure.
        result=await asyncio.wait_for(self.client.put(path,encoded,access='private',
            content_type='application/json',add_random_suffix=False,overwrite=False,multipart=False),timeout=20)
        if result.url!=self.origin+'/'+path or result.pathname!=path:raise ValueError('Journal location mismatch')
        self.records.append({'kind':kind,'id':ident,'sha256':sha256(encoded).hexdigest()})
