!function(){function d(a,b){var c=a.getRange(CodeMirror.Pos(b.line,b.ch-1),CodeMirror.Pos(b.line,b.ch+1));return 2==c.length?c:null}function e(a){var f,b={name:"autoCloseBrackets",Backspace:function(b){if(b.somethingSelected())return CodeMirror.Pass;var c=b.getCursor(),e=d(b,c);return e&&0==a.indexOf(e)%2?(b.replaceRange("",CodeMirror.Pos(c.line,c.ch-1),CodeMirror.Pos(c.line,c.ch+1)),void 0):CodeMirror.Pass}},e="";for(f=0;f<a.length;f+=2)!function(a,d){function f(b){var c=b.getSelection();b.replaceSelection(a+c+d)}function g(a){var b=a.getCursor(),c=a.getRange(b,CodeMirror.Pos(b.line,b.ch+1));return c!=d||a.somethingSelected()?CodeMirror.Pass:(a.execCommand("goCharRight"),void 0)}a!=d&&(e+=d),b["'"+a+"'"]=function(b){var h,i,j,k,l;if("'"==a&&"comment"==b.getTokenAt(b.getCursor()).type)return CodeMirror.Pass;if(b.somethingSelected())return f(b);if(a!=d||g(b)==CodeMirror.Pass)return h=b.getCursor(),i=CodeMirror.Pos(h.line,h.ch+1),j=b.getLine(h.line),k=j.charAt(h.ch),l=h.ch>0?j.charAt(h.ch-1):"",a==d&&CodeMirror.isWordChar(l)?CodeMirror.Pass:j.length==h.ch||e.indexOf(k)>=0||c.test(k)?(b.replaceSelection(a+d,{head:i,anchor:i}),void 0):CodeMirror.Pass},a!=d&&(b["'"+d+"'"]=g)}(a.charAt(f),a.charAt(f+1));return b}function f(a){return function(b){var c=b.getCursor(),e=d(b,c);return e&&0==a.indexOf(e)%2?(b.operation(function(){var a=CodeMirror.Pos(c.line+1,0);b.replaceSelection("\n\n",{anchor:a,head:a},"+input"),b.indentLine(c.line+1,null,!0),b.indentLine(c.line+2,null,!0)}),void 0):CodeMirror.Pass}}var a="()[]{}''\"\"",b="[]{}",c=/\s/;CodeMirror.defineOption("autoCloseBrackets",!1,function(c,d,g){var h,i,j;g!=CodeMirror.Init&&g&&c.removeKeyMap("autoCloseBrackets"),d&&(h=a,i=b,"string"==typeof d?h=d:"object"==typeof d&&(null!=d.pairs&&(h=d.pairs),null!=d.explode&&(i=d.explode)),j=e(h),i&&(j.Enter=f(i)),c.addKeyMap(j))})}();