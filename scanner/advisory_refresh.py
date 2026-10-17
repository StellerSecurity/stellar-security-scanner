"""Periodic known-malware lookups independent of commit scans.

Verify public registry identity before sending coordinates to advisory services.
This mode never fetches or executes archives and does not establish file safety.
"""
import hashlib
import json
import time

MAX_PLANS=10000
MAX_REQUESTS=1000
MAX_BYTES=64*1024*1024
MAX_SECONDS=300

class Incomplete(Exception):pass

def refresh(plans, acquisition, advisories, *, fetch=None, request=None, clock=time.monotonic, cargo=None):
    if not isinstance(plans,list) or len(plans)>MAX_PLANS:raise ValueError('invalid_refresh_plan')
    start=clock();seen=set();verified=[];gaps=[];count=0;consumed=0
    def budget():
        if clock()-start>=MAX_SECONDS:raise Incomplete('refresh_time_limit')
    def metadata(url,cap):
        nonlocal count,consumed
        budget();count+=1
        if count>MAX_REQUESTS or consumed>=MAX_BYTES:raise Incomplete('refresh_metadata_limit')
        cap=min(cap,MAX_BYTES-consumed)
        raw=(fetch or acquisition.public_fetch)(url,cap)
        if not isinstance(raw,bytes) or len(raw)>cap:raise Incomplete('refresh_metadata_limit')
        consumed+=len(raw);budget();return raw
    for plan in plans:
        budget()
        key=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if key in seen:continue
        seen.add(key)
        try:
            if isinstance(plan,dict) and plan.get('ecosystem')=='rust' and cargo is not None:
                try:
                    coordinate=cargo.verify(plan,fetch=metadata)
                except cargo.InvalidMetadata:
                    raise Incomplete('cargo_public_registry_binding_incomplete') from None
            else:
                coordinate=acquisition.acquire(plan,fetch=metadata,metadata_only=True)
            if coordinate.pop('archive_inspected',None) is not False:raise Incomplete('invalid_metadata_proof')
            verified.append(coordinate)
        except (acquisition.AcquisitionError,Incomplete) as exc:
            # Acquisition errors are fixed codes; never attach raw HTTP response text.
            gaps.append({'plan_sha256':key,'reason':str(exc)})
            if len(gaps)>=1000:break
    budget()
    def advisory_request(method,url,body,cap):
        nonlocal count,consumed
        if clock()-start>=MAX_SECONDS or count>=MAX_REQUESTS or consumed>=MAX_BYTES:
            raise advisories.AdvisoryError('refresh_work_limit')
        count+=1
        allowance=min(cap,MAX_BYTES-consumed)
        result=(request or advisories.public_request)(method,url,body,allowance)
        # Decoded transport output is bounded independently of compression and
        # HTTP Content-Length. Never include response data in an error.
        try:
            size=len(json.dumps(result,separators=(',',':'),ensure_ascii=True).encode())
        except (ValueError,TypeError,RecursionError):
            raise advisories.AdvisoryError('refresh_invalid_advisory_response') from None
        if size>allowance:
            raise advisories.AdvisoryError('refresh_advisory_byte_limit')
        consumed+=size
        if clock()-start>=MAX_SECONDS:
            raise advisories.AdvisoryError('refresh_time_limit')
        return result
    metadata_count=count
    result=advisories.check_packages(verified,request=advisory_request)
    return {'schema':1,'complete':not gaps and result['complete'],
        'checked_coordinates':len(verified),'malicious':result['malicious'],
        'gaps':gaps+result['gaps'],'metadata_requests':metadata_count,'total_requests':count,
        'package_archives_downloaded':False,'package_code_executed':False,
        'content_scan_performed':False,'ordinary_vulnerability_alerts_included':False}
