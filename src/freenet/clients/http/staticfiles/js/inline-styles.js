/**
 * inline-styles.js — applies dynamic values that cannot be expressed as
 * static CSS classes because they depend on server-side data.
 *
 * Uses data-* attributes set in the HTML instead of inline style=""
 * attributes so the page can comply with CSP "style-src 'self'".
 *
 * Also removes the "no-js" class from <body> so .jsonly elements appear.
 */
(function () {
    'use strict';
    var els, i;

    /* Let .jsonly elements appear now that JS is running */
    document.body.classList.remove('no-js');

    /* Progress bars: data-pct="N" → width: N% */
    els = document.querySelectorAll('[data-pct]');
    for (i = 0; i < els.length; i++) {
        els[i].style.width = els[i].getAttribute('data-pct') + '%';
    }

    /*
     * Peer-circle dot positions:
     *   data-abs-top="X" data-abs-left="Y" → top: Xpx; left: Ypx
     * position: absolute is already set via CSS (.absp / div.peercircle span.*)
     */
    els = document.querySelectorAll('[data-abs-top]');
    for (i = 0; i < els.length; i++) {
        els[i].style.top  = els[i].getAttribute('data-abs-top')  + 'px';
        els[i].style.left = els[i].getAttribute('data-abs-left') + 'px';
    }

    /* Histogram bar heights: data-bar-height="N%" → height: N% */
    els = document.querySelectorAll('[data-bar-height]');
    for (i = 0; i < els.length; i++) {
        els[i].style.height = els[i].getAttribute('data-bar-height');
    }
}());
