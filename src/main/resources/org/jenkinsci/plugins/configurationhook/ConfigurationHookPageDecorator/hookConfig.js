/*
 * The MIT License
 * 
 * Copyright (c) 2013 IKEDA Yasuyuki
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

YAHOO.namespace("org.jenkinsci.plugins.configurationhook");
// Whether submission should be hooked.
YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm = null;
YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit = true;

var forms = $$("form[name='config']");
if (forms && forms.length > 0) {
  for (var i = 0; i < forms.length; ++i) {
    var form = forms[i];
    form.observe("submit", function(evt){
      if (!YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit) {
        // already all hooks are processed.
        return;
      }
      
      if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm != null) {
        Event.stop(evt);
        return;
      }
      
      YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm = this;
      Event.fire(f,"jenkins:apply"); // give everyone a chance to write back to DOM
      buildFormTree(this);
      
      var origAction = this.action;
      
      try {
        this.action = $("configuration-hook-query").action;
        this.request({
          evalJS: true, // evaluate text/javascript contents.
        });
        Event.stop(evt);
      } finally {
        this.action = origAction;
      }
    });
  }
}
