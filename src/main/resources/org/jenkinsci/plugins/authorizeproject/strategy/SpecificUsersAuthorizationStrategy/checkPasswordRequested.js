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

/**
 * Show password field only when it is required.
 */
Behaviour.specify(".specific-user-authorization", "checkPasswordRequired", 0, function (e) {
  var findChild = function(startNode) {
    return function(src,filter) {
      return find(src,filter,function (e) {
        if (e.firstChild != null) {
          return e.firstChild;
        }
        while (e != null && e != startNode && e.nextSibling == null) {
          e = e.parentNode
        }
        if (e == null || e == startNode) {
            return null;
        }
        return e.nextSibling;
      });
    };
  };
  
  var useridField = findFormItem(e, "userid", findChild(e));
  var passwordField = findFormItem(e, "password", findChild(e));
  var passwordFieldBlock = findAncestor(passwordField, "TR");
  /*
    [JENKINS-64341] - In Jenkins version greater than 2.263.4
    the table tags for fields (in forms) were replaced by div tags.
    Since the changes were applied the 'findAncestor(passwordField, "TR")'
    method returns null. It is necessary to use the method
    'findAncestorClass(passwordField, "tr")' instead of.
  */
  if (passwordFieldBlock == null) {
      passwordFieldBlock = findAncestorClass(passwordField, "tr");
    }

  var passwordCheckBlock = findFollowingTR(passwordField, "validation-error-area");
  var passwordHelpBlock = findFollowingTR(passwordField, "help-area");

  var passwordBlockList = [
    passwordFieldBlock,
    passwordCheckBlock,
    passwordHelpBlock,
  ];
  
  passwordBlockList.forEach(function(f) {
    if (f != null) {
      f.style.display = 'none';
    }
  });
  
  var onchange = function(evt) {
    var url = useridField.getAttribute("checkPasswordRequestedUrl");
    url = eval(url);
    fetch(url, {
      method: "post",
      headers: crumb.wrap({}),
    }).then((rsp) => {
      if (rsp.ok) {
        rsp.json().then((required) => {
          if (required) {
            passwordBlockList.forEach(f => {
              if (f != null) {
                f.style.display = '';
              }
            });
          } else {
            passwordBlockList.forEach(f => {
              if (f != null) {
                f.style.display = 'none';
              }
            });
          }
        });
      }
    });
  };
  
  useridField.addEventListener("change", onchange);
  onchange.call(useridField);
});
