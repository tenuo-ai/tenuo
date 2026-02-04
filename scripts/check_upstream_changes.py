#!/usr/bin/env python3
"""
Check upstream integration repositories for recent changes.

Searches for breaking changes, deprecations, and API modifications.

Usage:
    python scripts/check_upstream_changes.py
    python scripts/check_upstream_changes.py --days 14
    python scripts/check_upstream_changes.py --integration openai
"""

import argparse
import sys
from datetime import datetime, timedelta
from typing import List, Dict

try:
    import requests
except ImportError:
    print("Error: requests library required")
    print("Install with: pip install requests")
    sys.exit(1)


INTEGRATIONS = {
    'openai': {
        'repo': 'openai/openai-python',
        'file': 'tenuo-python/tenuo/openai.py',
        'docs': 'https://github.com/openai/openai-python/releases'
    },
    'crewai': {
        'repo': 'joaomdmoura/crewAI',
        'file': 'tenuo-python/tenuo/crewai.py',
        'docs': 'https://github.com/joaomdmoura/crewAI/releases'
    },
    'autogen': {
        'repo': 'microsoft/autogen',
        'file': 'tenuo-python/tenuo/autogen.py',
        'docs': 'https://github.com/microsoft/autogen/releases'
    },
    'langchain': {
        'repo': 'langchain-ai/langchain',
        'file': 'tenuo-python/tenuo/langchain.py',
        'docs': 'https://python.langchain.com/changelog'
    },
    'langgraph': {
        'repo': 'langchain-ai/langgraph',
        'file': 'tenuo-python/tenuo/langgraph.py',
        'docs': 'https://github.com/langchain-ai/langgraph/releases'
    },
}

BREAKING_KEYWORDS = [
    'breaking', 'removed', 'deprecated', 'changed',
    'renamed', 'replaced', 'incompatible'
]


def check_releases(integration: str, days: int = 7) -> List[Dict]:
    """Check releases for an integration in the last N days."""
    info = INTEGRATIONS[integration]
    owner, repo = info['repo'].split('/')

    since = datetime.now() - timedelta(days=days)

    # GitHub API
    url = f'https://api.github.com/repos/{owner}/{repo}/releases'

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        releases = response.json()
    except requests.RequestException as e:
        print(f"⚠️  Error fetching releases for {integration}: {e}")
        return []

    recent_releases = []

    for release in releases:
        published = datetime.fromisoformat(release['published_at'].replace('Z', '+00:00'))

        if published.replace(tzinfo=None) < since:
            continue

        body = (release.get('body') or '').lower()
        found_keywords = [kw for kw in BREAKING_KEYWORDS if kw in body]

        recent_releases.append({
            'name': release['name'] or release['tag_name'],
            'tag': release['tag_name'],
            'published': published,
            'url': release['html_url'],
            'keywords': found_keywords,
            'body': release.get('body', ''),
        })

    return recent_releases


def print_report(integration: str, releases: List[Dict], verbose: bool = False):
    """Print formatted report for an integration."""
    if not releases:
        print("  ✅ No releases in the specified time period")
        return

    for release in releases:
        has_keywords = len(release['keywords']) > 0
        icon = "⚠️ " if has_keywords else "✅"

        print(f"\n  {icon} {release['name']}")
        print(f"     Published: {release['published'].strftime('%Y-%m-%d')}")
        print(f"     URL: {release['url']}")

        if has_keywords:
            print(f"     🚨 Keywords found: {', '.join(release['keywords'])}")

        if verbose and release['body']:
            # Print first 3 lines of release notes
            lines = release['body'].split('\n')[:3]
            print("     Preview:")
            for line in lines:
                if line.strip():
                    print(f"       {line[:80]}")


def main():
    parser = argparse.ArgumentParser(
        description='Check upstream integrations for recent changes'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days to look back (default: 7)'
    )
    parser.add_argument(
        '--integration',
        choices=list(INTEGRATIONS.keys()) + ['all'],
        default='all',
        help='Which integration to check (default: all)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show release note previews'
    )

    args = parser.parse_args()

    print("=" * 60)
    print(f"Checking upstream changes (last {args.days} days)")
    print("=" * 60)

    integrations_to_check = (
        list(INTEGRATIONS.keys()) if args.integration == 'all'
        else [args.integration]
    )

    total_releases = 0
    breaking_changes = 0

    for integration in integrations_to_check:
        print(f"\n📦 {integration.upper()}")
        print(f"   Repo: {INTEGRATIONS[integration]['repo']}")

        releases = check_releases(integration, args.days)
        total_releases += len(releases)
        breaking_changes += sum(1 for r in releases if r['keywords'])

        print_report(integration, releases, args.verbose)

    print("\n" + "=" * 60)
    print(f"Summary: {total_releases} releases, {breaking_changes} with breaking keywords")
    print("=" * 60)

    # Exit code
    if breaking_changes > 0:
        print("\n⚠️  Breaking changes detected! Review releases above.")
        sys.exit(1)
    else:
        print("\n✅ No breaking changes detected.")
        sys.exit(0)


if __name__ == '__main__':
    main()
