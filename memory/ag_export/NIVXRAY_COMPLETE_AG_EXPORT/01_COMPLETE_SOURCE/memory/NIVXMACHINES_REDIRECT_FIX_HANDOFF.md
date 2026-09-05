# NivX Machines — SEO Redirect Fix (URGENT, next session)

**Context:** Google Search Console flagged pages on `nivxmachines.com` as *"Page with redirect"* because they 301/302 to `cyberdefenders.com`. This kills SEO (source gets the ranking) and creates a copyright-flavored "aggregator without transformation" concern.

**Owner:** Next Emergent session pointed at the `nivxmachines.com` codebase (NOT the NivXRay codebase which is what `/app` currently holds).

---

## Fix in 4 steps

### 1. Find every redirect to cyberdefenders.com
Grep the `nivxmachines.com` codebase for:
```
cyberdefenders.com
window.location
meta http-equiv="refresh"
res.redirect
Response.Redirect
```
Every hit is a candidate for replacement.

### 2. Replace each redirect with an original commentary page

Use this Next.js/React template (or the equivalent for whatever stack the site is on):

```jsx
export default function ChallengeCommentary({ challenge }) {
  return (
    <article className="nvxm-commentary">
      <h1>{challenge.originalTitle}</h1>
      <p className="meta">
        NivX Machines Analysis · Published {challenge.publishedAt}
      </p>

      <section className="tldr">
        <h2>What this challenge teaches</h2>
        <p>{challenge.ourTldr}</p>
      </section>

      <section className="approach">
        <h2>Our walkthrough approach</h2>
        <div dangerouslySetInnerHTML={{ __html: challenge.ourAnalysis }} />
      </section>

      <section className="references">
        <h2>Reference sources</h2>
        <ul>
          <li>
            Original challenge:{" "}
            <a href={challenge.sourceUrl}
               rel="noopener nofollow noreferrer"
               target="_blank">
              CyberDefenders — {challenge.originalTitle}
            </a>
          </li>
        </ul>
      </section>

      <link rel="canonical" href={`https://nivxmachines.com/challenges/${challenge.slug}`} />
    </article>
  );
}
```

**Rules:**
- **No** `window.location`, **no** `<meta refresh>`, **no** server-side 3xx to cyberdefenders
- Every external link uses `rel="noopener nofollow noreferrer" target="_blank"`
- Every page has a `<link rel="canonical" href="https://nivxmachines.com/…" />`
- Every page has ≥200 words of original analysis (this is the fair-use "commentary" moat)

### 3. Sitemap.xml + robots.txt
- Regenerate `sitemap.xml` with ONLY the new original-content URLs
- Delete any redirect-only URLs from the sitemap
- Resubmit sitemap at Google Search Console → Sitemaps

### 4. Global footer disclaimer
Add to `<footer>` on every page:
```
NivX Machines · Independent analysis. External sources are cited
and used under fair-use commentary. Trademarks belong to their
respective owners. Analysis, scoring, and commentary © NivX Machines 2026.
```

---

## Verification checklist

After the sweep:
- [ ] `grep -r "cyberdefenders.com" nivxmachines.com/ | grep -iE "location|redirect|refresh"` returns **zero** matches (only references in text/href, not redirects)
- [ ] Every `/challenges/*` route renders the commentary template
- [ ] Every page has a self-referencing `<link rel="canonical">`
- [ ] `sitemap.xml` contains only content pages, no redirect pages
- [ ] Search Console → Request Indexing on 5 sample URLs

## Expected outcome (in 2-6 weeks)
- Google removes "Page with redirect" flag
- Pages start ranking on their own for challenge-adjacent queries
- Traffic that used to leak to cyberdefenders.com now stays on nivxmachines.com
- Fair-use commentary provides legal cover
