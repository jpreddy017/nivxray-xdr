# On-demand trajectory loading

Extends reviewed3bbc5c8/21e5861 without changing backend contracts or the approved layout. Horizontal wheel/trackpad gestures toward older evidence at the timeline's left edge and upward gestures at the Activity list's top request one older page. The explicit load/retry button remains available for keyboard/touch access and empty filtered views. Render, resize and programmatic scrolling do not initiate paging. No eager full-history download.

Single-flight ref prevents duplicate calls before React commits state; endpoint/time-window changes abort older reads and ignore stale replies. Unavailable or nonadvancing cursors preserve existing evidence and require explicit retry. Event-identity anchors preserve horizontal timeline and vertical activity position on prepend. Counts report loaded events, and search emptiness explicitly applies only to loaded data. Filters remain local to loaded evidence; this change does not claim full-history search.

Validation: actual React component suites cover edge gestures, modifier exclusion, anchors, concurrent demand, explicit failure retry, stale cancellation, nonadvancing cursor, and actual model parent-instance reconstruction and deduplication across pages. No new backend code. This successor still requires independent review and authenticated browser validation; it is not deployed to production. Existing preservation and clean deployment payload blockers remain.

Public reference: Cisco engineering's2018 Device Trajectory V2 announcement documents loading on demand during timeline scrolling: https://blogs.cisco.com/security/amp-for-endpoints-updates-fall-2018 . This does not reveal Cisco's backend implementation or imply a latency guarantee.
