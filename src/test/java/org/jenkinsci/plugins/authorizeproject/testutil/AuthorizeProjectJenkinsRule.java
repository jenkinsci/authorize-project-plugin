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

package org.jenkinsci.plugins.authorizeproject.testutil;

import hudson.model.Describable;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import jenkins.security.QueueItemAuthenticatorConfiguration;

import org.jenkinsci.plugins.authorizeproject.ProjectQueueItemAuthenticator;
import org.jvnet.hudson.test.JenkinsRule;

import com.gargoylesoftware.htmlunit.WebResponse;

/**
 *
 */
public class AuthorizeProjectJenkinsRule extends JenkinsRule {
    private Map<Class<? extends Describable<?>>, Boolean> strategyEnabledMapByClass;
    
    public AuthorizeProjectJenkinsRule() {
        this(Collections.<Class<? extends Describable<?>>, Boolean>emptyMap());
    }
    
    public AuthorizeProjectJenkinsRule(Class<? extends Describable<?>>... strategiesToEnabled) {
        this(new HashMap<Class<? extends Describable<?>>, Boolean>());
        for(Class<? extends Describable<?>> strategy: strategiesToEnabled) {
            this.strategyEnabledMapByClass.put(strategy, true);
        }
    }
    
    public AuthorizeProjectJenkinsRule(Map<Class<? extends Describable<?>>, Boolean> strategyEnabledMapByClass) {
        this.strategyEnabledMapByClass = strategyEnabledMapByClass;
    }
    
    @Override
    public WebClient createWebClient() {
        return new WebClient() {
            private static final long serialVersionUID = 3389654318647204218L;
            
            @Override
            public void throwFailingHttpStatusCodeExceptionIfNecessary(WebResponse webResponse) {
                // 405 Method Not Allowed is returned when parameter is required.
                if (webResponse.getStatusCode() == 405) {
                    return;
                }
                super.throwFailingHttpStatusCodeExceptionIfNecessary(webResponse);
            }
        };
    }
    
    public void before() throws Throwable {
        super.before();
        Map<String, Boolean> strategyEnabledMap = new HashMap<String, Boolean>();
        for(Entry<Class<? extends Describable<?>>, Boolean> e: strategyEnabledMapByClass.entrySet()) {
            strategyEnabledMap.put(
                    jenkins.getDescriptor(e.getKey()).getId(),
                    e.getValue()
            );
        }
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().add(new ProjectQueueItemAuthenticator(strategyEnabledMap));
    }
}
