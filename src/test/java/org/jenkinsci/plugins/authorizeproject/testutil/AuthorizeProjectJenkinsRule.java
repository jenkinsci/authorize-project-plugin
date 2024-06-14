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
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import org.htmlunit.WebResponse;
import org.jenkinsci.plugins.authorizeproject.ProjectQueueItemAuthenticator;
import org.jvnet.hudson.test.JenkinsRule;

public class AuthorizeProjectJenkinsRule extends JenkinsRule {
    private Set<Class<? extends Describable<?>>> enabledStrategiesByClass;
    private Set<Class<? extends Describable<?>>> disabledStrategiesByClass;

    public AuthorizeProjectJenkinsRule() {
        this(Set.of(), Set.of());
    }

    @SafeVarargs
    public AuthorizeProjectJenkinsRule(Class<? extends Describable<?>>... enabledStrategiesByClass) {
        this(Stream.of(enabledStrategiesByClass).collect(Collectors.toSet()), Set.of());
    }

    public AuthorizeProjectJenkinsRule(
            Set<Class<? extends Describable<?>>> enabledStrategiesByClass,
            Set<Class<? extends Describable<?>>> disabledStrategiesByClass) {
        this.enabledStrategiesByClass = enabledStrategiesByClass;
        this.disabledStrategiesByClass = disabledStrategiesByClass;
    }

    @Override
    public WebClient createWebClient() {
        WebClient webClient = new WebClient() {
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
        webClient.getOptions().setFetchPolyfillEnabled(true);
        return webClient;
    }

    public void before() throws Throwable {
        super.before();
        Set<String> enabledStrategies = new HashSet<>();
        Set<String> disabledStrategies = new HashSet<>();
        for (Class<? extends Describable<?>> clazz : enabledStrategiesByClass) {
            enabledStrategies.add(jenkins.getDescriptor(clazz).getId());
        }
        for (Class<? extends Describable<?>> clazz : disabledStrategiesByClass) {
            disabledStrategies.add(jenkins.getDescriptor(clazz).getId());
        }
        QueueItemAuthenticatorConfiguration.get()
                .getAuthenticators()
                .add(new ProjectQueueItemAuthenticator(enabledStrategies, disabledStrategies));
    }
}
