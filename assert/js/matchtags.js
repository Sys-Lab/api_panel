!function(){"use strict";function a(a){a.state.tagHit&&a.state.tagHit.clear(),a.state.tagOther&&a.state.tagOther.clear(),a.state.tagHit=a.state.tagOther=null}function b(b){b.state.failedTagMatch=!1,b.operation(function(){var c,d,e,f,g;a(b),b.somethingSelected()||(c=b.getCursor(),d=b.getViewport(),d.from=Math.min(d.from,c.line),d.to=Math.max(c.line+1,d.to),e=CodeMirror.findMatchingTag(b,c,d),e&&(b.state.matchBothTags&&(f="open"==e.at?e.open:e.close,f&&(b.state.tagHit=b.markText(f.from,f.to,{className:"CodeMirror-matchingtag"}))),g="close"==e.at?e.open:e.close,g?b.state.tagOther=b.markText(g.from,g.to,{className:"CodeMirror-matchingtag"}):b.state.failedTagMatch=!0))})}function c(a){a.state.failedTagMatch&&b(a)}CodeMirror.defineOption("matchTags",!1,function(d,e,f){f&&f!=CodeMirror.Init&&(d.off("cursorActivity",b),d.off("viewportChange",c),a(d)),e&&(d.state.matchBothTags="object"==typeof e&&e.bothTags,d.on("cursorActivity",b),d.on("viewportChange",c),b(d))}),CodeMirror.commands.toMatchingTag=function(a){var c,b=CodeMirror.findMatchingTag(a,a.getCursor());b&&(c="close"==b.at?b.open:b.close,c&&a.setSelection(c.to,c.from))}}();