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

package org.jenkinsci.plugins.configurationhook;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import jenkins.model.Jenkins;

import org.jenkinsci.plugins.configurationhook.ConfigurationHook.HookInfo;
import org.kohsuke.stapler.Ancestor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import hudson.Extension;
import hudson.model.PageDecorator;

/**
 *
 */
@Extension
public class ConfigurationHookPageDecorator extends PageDecorator {
    public String getQueryUrl(StaplerRequest req) {
        return String.format("%s/%s/%s", getCurrentDescriptorByNameUrl(), getDescriptorUrl(), "query");
    }
    
    public List<ConfigurationHook<?>> getHooks(StaplerRequest req) {
        // for what object is this page?
        List<Ancestor> ancestors = req.getAncestors();
        if (ancestors == null || ancestors.isEmpty()) {
            return Collections.emptyList();
        }
        
        Object target = ancestors.get(ancestors.size() - 1).getObject();
        
        return getHooksFor(target);
    }
    
    @SuppressWarnings("unchecked")
    protected <T>List<ConfigurationHook<? extends T>> getHooksFor(T target) {
        List<ConfigurationHook<? extends T>> hooks = new ArrayList<ConfigurationHook<? extends T>>();
        for(ConfigurationHook<?> hook: Jenkins.getInstance().getExtensionList(ConfigurationHook.class)) {
            Class<?> clazz = hook.getTargetType();
            if (clazz.isAssignableFrom(target.getClass())) {
                hooks.add((ConfigurationHook<? extends T>)hook);
            }
        }
        return hooks;
    }
    
    public void doQuery(StaplerRequest req, StaplerResponse rsp) throws IOException {
        // for what object is this query?
        // The last object is myself (ConfigurationHookPageDecorator).
        // The one before that is target object.
        List<Ancestor> ancestors = req.getAncestors();
        if (ancestors == null || ancestors.size() < 2) {
            return;
        }
        
        Object target = ancestors.get(ancestors.size() - 2).getObject();
        for(ConfigurationHook<?> hook: getHooksFor(target)) {
            HookInfo info = hook.prepareHookRaw(target, req);
            if (info != null) {
                // found a hook!
                rsp.setContentType("text/javascript");
                rsp.getWriter().println(
                        String.format(
                                "YAHOO.org.jenkinsci.plugins.configurationhook.showPopup('%s', '%s')",
                                hook.getPopupId(),
                                info.getTitle()
                        )
                );
                return;
            }
        }
        rsp.setContentType("text/javascript");
        rsp.getWriter().println(
                "(function(){"
                + "var form = YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm;"
                + "YAHOO.org.jenkinsci.plugins.configurationhook.hookSubmit = false;"
                + "YAHOO.org.jenkinsci.plugins.configurationhook.suspendedForm = null;"
                + "form.submit();"
                + "})();"
        );
    }
}
