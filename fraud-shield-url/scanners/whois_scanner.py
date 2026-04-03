"""WHOIS lookup for domain age and registration analysis"""
import logging
import whois
from datetime import datetime, timezone
from typing import Optional
from models import WHOISFinding

logger = logging.getLogger(__name__)

class WHOISScanner:
    
    def __init__(self):
        pass
    
    async def scan(self, url: str) -> Optional[WHOISFinding]:
        try:
            from urllib.parse import urlparse
            import asyncio
            
            domain = urlparse(url).netloc
            # Strip www.
            if domain.startswith("www."):
                domain = domain[4:]
            
            # whois is blocking, run in thread pool
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            
            # Domain creation date
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            
            # Calculate domain age in days
            domain_age_days = None
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                domain_age_days = (datetime.now(timezone.utc) - created).days
            
            # Expiry date
            expires = w.expiration_date
            if isinstance(expires, list):
                expires = expires[0]
            
            return WHOISFinding(
                domain=domain,
                registrar=w.registrar,
                creation_date=str(created) if created else None,
                expiration_date=str(expires) if expires else None,
                domain_age_days=domain_age_days,
                country=w.country,
                name_servers=w.name_servers if isinstance(w.name_servers, list) else [],
            )
        
        except Exception as e:
            logger.error(f"WHOIS scan error: {str(e)}")
            return WHOISFinding(domain=url, errors=[str(e)])
