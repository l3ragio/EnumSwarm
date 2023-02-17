#waybackurls in python:
# -----------------
import datetime
import json
import urllib.parse
import urllib.request
import argparse
import sys
import time
import threading
import requests


from typing import Callable, List, Tuple
import urllib.parse


class Wurl:
    def __init__(self, date: str, url: str):
        self.date = date
        self.url = url


FetchFn = Callable[[str, bool], Tuple[List[Wurl], Exception]]


def get_wayback_urls(domain: str, no_subs: bool) -> Tuple[List[Wurl], Exception]:
    subs_wildcard = "*." if not no_subs else ""
    url = f"http://web.archive.org/cdx/search/cdx?url={subs_wildcard}{domain}/*&output=json&collapse=urlkey"

    try:
        with urllib.request.urlopen(url) as response:
            raw = response.read()

        wrapper = json.loads(raw)

        out = []
        skip = True
        for urls in wrapper:
            if skip:
                skip = False
                continue
            out.append(Wurl(date=urls[1], url=urls[2]))

        return out, None

    except Exception as e:
        return [], e



def get_common_crawl_urls(domain: str, no_subs: bool) -> Tuple[List[Wurl], Exception]:
    subs_wildcard = "*." if not no_subs else ""
    url = f"http://index.commoncrawl.org/CC-MAIN-2018-22-index?url={subs_wildcard}{domain}/*&output=json"

    try:
        with urllib.request.urlopen(url) as response:
            out = []
            for line in response:
                wrapper = json.loads(line.decode('utf-8'))
                out.append(Wurl(date=wrapper['timestamp'], url=wrapper['url']))
        return out, None

    except Exception as e:
        return [], e

from typing import List, Tuple
import os


def get_virus_total_urls(domain: str, no_subs: bool) -> Tuple[List[Wurl], Exception]:
    out = []

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        # no API key isn't an error,
        # just don't fetch
        return out, None

    fetch_url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
    try:
        with urllib.request.urlopen(fetch_url) as response:
            wrapper = json.loads(response.read().decode())
            for u in wrapper['detected_urls']:
                out.append(Wurl(url=u['url']))
        return out, None

    except Exception as e:
        return [], e

from urllib.parse import urlparse

def isSubdomain(rawUrl, domain):
    u = urlparse(rawUrl)
    if u.scheme == "" or u.netloc == "":
        # we can't parse the URL so just
        # err on the side of including it in output
        return False

    return u.hostname.lower() != domain.lower()


def getVersions(u: str) -> list:
    out = []
    resp = requests.get(f"http://web.archive.org/cdx/search/cdx?url={u}&output=json")
    
    if resp.status_code != 200:
        return out, Exception(f"Error fetching URL {u}: status code {resp.status_code}")
    
    r = json.loads(resp.content)
    
    first = True
    seen = {}
    
    for s in r:
        # skip the first element, it's the field names
        if first:
            first = False
            continue
        
        # fields: "urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"
        if s[5] in seen:
            continue
        
        seen[s[5]] = True
        out.append(f"https://web.archive.org/web/{s[1]}if_/{s[2]}")
    
    return out

def waybackurls(domains, dates=False, noSubs=False, getVersionsFlag=False):



    # get-versions mode
    if getVersionsFlag:

        for u in domains:
            versions, err = getVersions(u)
            if err is not None:
                continue
            print("\n".join(versions))

        return

    fetchFns = [
        get_wayback_urls,
        get_common_crawl_urls,
        get_virus_total_urls,
    ]

    for domain in domains:

        wurls = []

        for fetch in fetchFns:
            resp, err = fetch(domain, noSubs)
            if err is not None:
                continue
            for r in resp:
                if noSubs and isSubdomain(r.url, domain):
                    continue
                wurls.append(r)

        seen = {}
        for w in wurls:
            if w.url in seen:
                continue
            seen[w.url] = True

            if dates:

                try:
                    d = datetime.datetime.strptime(w.date, "%Y%m%d%H%M%S")
                except ValueError:
                    print(f"failed to parse date [{w.date}] for URL [{w.url}]")
                    continue

                print(f"{d.isoformat()} {w.url}")

            else:
                print(w.url)
        
    return list(seen.keys())


# waybackurls()
# -------------------