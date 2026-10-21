"""Google Web Risk Lookup only; never use the differently priced Update API."""
import httpx

from app.core.config import settings


async def query_web_risk(url: str) -> dict:
    result = {'provider': 'google_web_risk', 'available': False, 'data': {}}
    if not settings.GOOGLE_WEB_RISK_API_KEY:
        return result
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(
                'https://webrisk.googleapis.com/v1/uris:search',
                headers={'X-Goog-Api-Key': settings.GOOGLE_WEB_RISK_API_KEY},
                params=[('uri', url)] + [('threatTypes', value) for value in
                    ('MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE')],
            )
            if response.status_code != 200:
                return result
            payload = response.json()
            if not isinstance(payload, dict):
                return result
            if set(payload) - {'threat'}:
                return result
            threat = payload.get('threat', {})
            if not isinstance(threat, dict):
                return result
            types = threat.get('threatTypes', [])
            if (not isinstance(types, list)
                    or any(t not in ('MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE') for t in types)
                    or ('threat' in payload and not types)):
                return result
            return {**result, 'available': True, 'data': {
                'is_malicious': bool(types), 'score': 100 if types else 0,
                'threat_types': types, 'status': 'detected' if types else 'no_match',
            }}
    except (httpx.HTTPError, ValueError):
        # Never include exception strings: they may contain the URL or key.
        return result
