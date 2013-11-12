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

// the form now suspending.
YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm = null;

// the popup window now displaying.
YAHOO.org.jenkinsci.plugins.configurationhook.popup = null;

// show popup.
YAHOO.org.jenkinsci.plugins.configurationhook.showPopup = function(popupId, title) {
  YAHOO.org.jenkinsci.plugins.configurationhook.popup = new YAHOO.widget.Panel(
    "configurationHookForm",
    {
      width:"720px",
      fixedcenter:true,
      close:false,
      draggable:false,
      zindex:4,
      modal:true
    }
  );
  var popup = YAHOO.org.jenkinsci.plugins.configurationhook.popup;
  popup.setHeader(title);
  popup.setBody($(popupId).innerHTML);
  popup.showEvent.subscribe(
    function(){
      this.element.getElementsBySelector("input[name='targetJson']")[0].setValue(
        YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm['json'].getValue()
      );
      this.element.getElementsBySelector("input[name='submit']")[0].on(
        'click',
        function(evt) {
          this.form['command'].setValue('submit');
          buildFormTree(this.form);
          this.form.request({
            evalJS: false, // evaluate contents.
            onSuccess: function(response) {
                eval(response.responseText); // this must be evaluated first.
                YAHOO.org.jenkinsci.plugins.configurationhook.popup.hide();
                YAHOO.org.jenkinsci.plugins.configurationhook.popup = null;
                YAHOO.org.jenkinsci.plugins.configurationhook.retrySubmit();
            },
          });
          Event.stop(evt);
        }
      );
      this.element.getElementsBySelector("input[name='cancel']")[0].on(
        'click',
        function(evt) {
          this.form['command'].setValue('cancel');
          buildFormTree(this.form);
          this.form.request({
            evalJS: true, // evaluate text/javascript contents.
            onSuccess: function(response) {
                YAHOO.org.jenkinsci.plugins.configurationhook.popup.hide();
                YAHOO.org.jenkinsci.plugins.configurationhook.popup = null;
                YAHOO.org.jenkinsci.plugins.configurationhook.cancelSubmit();
            },
          });
          Event.stop(evt);
        }
      );
    },
    popup
  );
  popup.render(document.body);
}

// called when hooking the submission.
YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit = function(form) {
  if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm != null) {
    // Hooking process is already in progress.
    // ignore this submission.
    return;
  }
  
  YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm = form;
  Event.fire(form,"jenkins:apply"); // give everyone a chance to write back to DOM
  buildFormTree(form);
  
  var queryForm = $("configuration-hook-query");
  queryForm.elements["json"].setValue(form.elements["json"].getValue());
  queryForm.request({
    evalJS: true, // evaluate text/javascript contents.
  });
};

YAHOO.org.jenkinsci.plugins.configurationhook.retrySubmit = function() {
  if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm == null) {
    return;
  }
  var form = YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm;
  YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm = null;
  YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit(form);
}

YAHOO.org.jenkinsci.plugins.configurationhook.resumeSubmit = function() {
  if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm == null) {
    return;
  }
  var form = YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm;
  YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm = null;
  form.submit();
}

YAHOO.org.jenkinsci.plugins.configurationhook.cancelSubmit = function() {
  if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm == null) {
    return;
  }
  YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm = null;
}

var forms = $$("form[name='config']");
if (forms && forms.length > 0) {
  for (var i = 0; i < forms.length; ++i) {
    var form = forms[i];
    
    form.observe("submit", function(evt){
      YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit(this);
      evt.stop();
    });
  }
}
