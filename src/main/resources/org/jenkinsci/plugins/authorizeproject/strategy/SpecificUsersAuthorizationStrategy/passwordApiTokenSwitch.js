/*
 * The MIT License
 * 
 * Copyright (c) 2015 IKEDA Yasuyuki
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
 * Swtich password and ApiToken
 */
Behaviour.specify(".specific-user-authorization", "passwordApiTokenSwitch", 0, function (e) {
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
  
  var onchange = function() {
    var e = this.up(".specific-user-authorization");
    if (this.checked) {
        e.down('.specific-user-authorization-password').hide();
        e.down('.specific-user-authorization-apitoken').show();
    } else {
        e.down('.specific-user-authorization-password').show();
        e.down('.specific-user-authorization-apitoken').hide();
    }
  };
  
  var useApitokenField = findFormItem(e, "useApitoken", findChild(e));
  useApitokenField.observe("click", onchange);
  onchange.call(useApitokenField);
});
