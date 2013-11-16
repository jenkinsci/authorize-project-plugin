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

// the form now suspending.
// {
//    form: form,
//    resubmit: function to resubmit form,
// }
YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo = null;

// the form no longer needed to hook.
YAHOO.org.jenkinsci.plugins.configurationhook.passedForm = null;

// the popup window now displaying.
YAHOO.org.jenkinsci.plugins.configurationhook.popup = null;

// simulate form submission.
YAHOO.org.jenkinsci.plugins.configurationhook.simulateSubmit = function(form) {
  if (form.dispatchEvent) {
    var event = document.createEvent("HTMLEvents");
    event.initEvent("submit", true, true);
    if (form.dispatchEvent(event)) {
      form.submit();
    }
  } else if (form.fireEvent) {
    // IE
    if (form.fireEvent("onsubmit")) {
      form.submit();
   }
  } else {
    if (form.onsubmit()) {
      form.submit();
    }
  }
}

// simulate button click.
YAHOO.org.jenkinsci.plugins.configurationhook.simulateClick = function(button) {
  if (button.dispatchEvent) {
    var event = document.createEvent("HTMLEvents");
    event.initEvent("click", true, true);
    if (button.dispatchEvent(event)) {
      button.click();
    }
  } else if (button.fireEvent) {
    // IE
    if (button.fireEvent("onclick")) {
      button.click();
    }
  } else {
    if (button.onclick()) {
      button.click();
    }
  }
}

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
        YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo['form']['json'].getValue()
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
YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit = function(form, resubmit) {
  if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo != null) {
    // Hooking process is already in progress.
    // ignore this submission.
    return false;
  }
  
  YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo = {
    form: form,
    resubmit: resubmit,
  }
  
  Event.fire(form,"jenkins:apply"); // give everyone a chance to write back to DOM
  buildFormTree(form);
  
  var queryForm = $("configuration-hook-query");
  queryForm.elements["json"].setValue(form.elements["json"].getValue());
  queryForm.request({
    evalJS: true, // evaluate text/javascript contents.
  });
  
  return false;
};

YAHOO.org.jenkinsci.plugins.configurationhook.retrySubmit = function() {
  if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo == null) {
    return;
  }
  var formInfo = YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo;
  YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo = null;
  if (YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit(formInfo.form, formInfo.resubmit)) {
    formInfo.resubmit();
  }
}

YAHOO.org.jenkinsci.plugins.configurationhook.resumeSubmit = function() {
  if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo == null) {
    return;
  }
  var formInfo = YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo;
  YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo = null;
  formInfo.resubmit();
}

YAHOO.org.jenkinsci.plugins.configurationhook.cancelSubmit = function() {
  if (YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo == null) {
    return;
  }
  YAHOO.org.jenkinsci.plugins.configurationhook.suspendedFormInfo = null;
}

Behaviour.specify(".submit-button button", 'hookconfig-submit', 100, function (e) {
  var replace = e.clone(true);
  e.parentElement.appendChild(replace);
  replace.cloneFrom = e;
  e.hide();
  replace.observe("click", function(evt) {
    evt.stop();
    var cloneFrom = this.cloneFrom;
    if(
      YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit(cloneFrom.form, function() {
        YAHOO.org.jenkinsci.plugins.configurationhook.simulateClick(cloneFrom);
      })
    ) {
      YAHOO.org.jenkinsci.plugins.configurationhook.simulateClick(cloneFrom);
    }
  });
});

Behaviour.specify(".apply-button button", "hookconfig-apply", 100, function (e) {
  var replace = e.clone(true);
  e.parentElement.appendChild(replace);
  replace.cloneFrom = e;
  e.hide();
  replace.observe("click", function(evt) {
    evt.stop();
    var cloneFrom = this.cloneFrom;
    if(
      YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit(cloneFrom.form, function() {
        YAHOO.org.jenkinsci.plugins.configurationhook.simulateClick(cloneFrom);
      })
    ) {
      YAHOO.org.jenkinsci.plugins.configurationhook.simulateClick(cloneFrom);
    }
  });
});

