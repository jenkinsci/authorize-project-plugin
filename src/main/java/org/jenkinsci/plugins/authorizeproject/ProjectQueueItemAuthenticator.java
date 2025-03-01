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

package org.jenkinsci.plugins.authorizeproject;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.DescriptorVisibilityFilter;
import hudson.model.Job;
import hudson.model.Queue;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.core.Authentication;

/**
 * Authorize builds of projects configured with {@link AuthorizeProjectProperty}.
 */
public class ProjectQueueItemAuthenticator extends QueueItemAuthenticator {
    private final Set<String> enabledStrategies;
    private final Set<String> disabledStrategies;

    @Deprecated
    private transient Map<String, Boolean> strategyEnabledMap;

    /**
     *
     */
    @Deprecated
    public ProjectQueueItemAuthenticator() {
        this(Set.of(), Set.of());
    }

    @Deprecated
    public ProjectQueueItemAuthenticator(Map<String, Boolean> strategyEnabledMap) {
        this(
                strategyEnabledMap.entrySet().stream()
                        .filter(e -> e.getValue().equals(true))
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toSet()),
                strategyEnabledMap.entrySet().stream()
                        .filter(e -> e.getValue().equals(false))
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toSet()));
    }

    @DataBoundConstructor
    public ProjectQueueItemAuthenticator(Set<String> enabledStrategies, Set<String> disabledStrategies) {
        this.enabledStrategies = enabledStrategies;
        this.disabledStrategies = disabledStrategies;
    }

    protected Object readResolve() {
        if (strategyEnabledMap != null) {
            return new ProjectQueueItemAuthenticator(strategyEnabledMap);
        }
        return this;
    }

    /**
     * @see jenkins.security.QueueItemAuthenticator#authenticate2(hudson.model.Queue.Item)
     */
    @Override
    @CheckForNull
    public Authentication authenticate2(Queue.Item item) {
        if (!(item.task instanceof Job)) {
            return null;
        }
        Job<?, ?> project = (Job<?, ?>) item.task;
        if (project instanceof AbstractProject<?, ?> abstractProject) {
            project = abstractProject.getRootProject();
        }
        AuthorizeProjectProperty prop = project.getProperty(AuthorizeProjectProperty.class);
        if (prop == null) {
            return null;
        }
        return prop.authenticate(item);
    }

    @Deprecated
    public Map<String, Boolean> getStrategyEnabledMap() {
        Map<String, Boolean> strategyEnabledMap = new HashMap<>();
        for (String strategy : enabledStrategies) {
            strategyEnabledMap.put(strategy, true);
        }
        for (String strategy : disabledStrategies) {
            strategyEnabledMap.put(strategy, false);
        }
        return strategyEnabledMap;
    }

    public Set<String> getEnabledStrategies() {
        return enabledStrategies;
    }

    public Set<String> getDisabledStrategies() {
        return disabledStrategies;
    }

    public boolean isStrategyEnabled(Descriptor<?> d) {
        if (enabledStrategies.contains(d.getId())) {
            return true;
        }

        if (disabledStrategies.contains(d.getId())) {
            return false;
        }

        if (d instanceof AuthorizeProjectStrategyDescriptor descriptor) {
            return descriptor.isEnabledByDefault();
        }

        return true;
    }

    /**
     *
     */
    @Extension
    public static class DescriptorImpl extends QueueItemAuthenticatorDescriptor {
        /**
         * @return the name shown in the security configuration page.
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName() {
            return Messages.ProjectQueueItemAuthenticator_DisplayName();
        }

        @Deprecated
        public List<AuthorizeProjectStrategyDescriptor> getDescriptorsForGlobalSecurityConfigPage() {
            return AuthorizeProjectStrategyDescriptor.getDescriptorsForGlobalSecurityConfigPage();
        }

        /**
         * @return all installed {@link AuthorizeProjectStrategy}
         */
        public List<Descriptor<AuthorizeProjectStrategy>> getAvailableDescriptorList() {
            return AuthorizeProjectStrategy.all();
        }

        /**
         * Creates new {@link ProjectQueueItemAuthenticator} from inputs.
         * Additional to that, configure global configurations of {@link AuthorizeProjectStrategy}.
         *
         * @param req the request.
         * @param formData the form data.
         * @return the authenticator.
         * @throws hudson.model.Descriptor.FormException if the submitted form is invalid.
         * @see hudson.model.Descriptor#newInstance(org.kohsuke.stapler.StaplerRequest2, net.sf.json.JSONObject)
         */
        @Override
        public ProjectQueueItemAuthenticator newInstance(StaplerRequest2 req, JSONObject formData)
                throws FormException {
            Set<String> enabledStrategies = new HashSet<>();
            Set<String> disabledStrategies = new HashSet<>();

            for (Descriptor<AuthorizeProjectStrategy> d : getAvailableDescriptorList()) {
                String name = d.getJsonSafeClassName();
                if (formData.has(name)) {
                    enabledStrategies.add(d.getId());
                    if (d instanceof AuthorizeProjectStrategyDescriptor descriptor
                            && descriptor.getGlobalSecurityConfigPage() != null) {
                        descriptor.configureFromGlobalSecurity(req, formData.getJSONObject(name));
                    }
                } else {
                    disabledStrategies.add(d.getId());
                }
            }

            return new ProjectQueueItemAuthenticator(enabledStrategies, disabledStrategies);
        }
    }

    /**
     * @return instance configured in Global Security configuration.
     */
    public static ProjectQueueItemAuthenticator getConfigured() {
        for (QueueItemAuthenticator authenticator :
                QueueItemAuthenticatorConfiguration.get().getAuthenticators()) {
            if (authenticator instanceof ProjectQueueItemAuthenticator itemAuthenticator) {
                return itemAuthenticator;
            }
        }
        return null;
    }

    /**
     * @return whether Jenkins is configured to use {@link ProjectQueueItemAuthenticator}.
     */
    public static boolean isConfigured() {
        return getConfigured() != null;
    }

    @Extension
    public static class DescriptorVisibilityFilterImpl extends DescriptorVisibilityFilter {
        @Override
        public boolean filter(Object context, @SuppressWarnings("rawtypes") Descriptor descriptor) {
            if (!(context instanceof ProjectQueueItemAuthenticator)) {
                return true;
            }
            return ((ProjectQueueItemAuthenticator) context).isStrategyEnabled(descriptor);
        }
    }
}
