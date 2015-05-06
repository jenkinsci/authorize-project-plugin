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

import java.util.List;

import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.Job;
import hudson.model.Queue;

import javax.annotation.CheckForNull;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import jenkins.security.QueueItemAuthenticatorConfiguration;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import jenkins.security.QueueItemAuthenticator;

/**
 * Authorize builds of projects configured with {@link AuthorizeProjectProperty}.
 */
public class ProjectQueueItemAuthenticator extends QueueItemAuthenticator {
    /**
     * 
     */
    @DataBoundConstructor
    public ProjectQueueItemAuthenticator() {
    }
    
    /**
     * @param item
     * @return
     * @see jenkins.security.QueueItemAuthenticator#authenticate(hudson.model.Queue.Item)
     */
    @Override
    @CheckForNull
    public Authentication authenticate(Queue.Item item) {
        if (!(item.task instanceof Job)) {
            return null;
        }
        Job<?, ?> project = (Job<?,?>)item.task;
        if (project instanceof AbstractProject) {
            project = ((AbstractProject<?,?>)project).getRootProject();
        }
        AuthorizeProjectProperty prop = project.getProperty(AuthorizeProjectProperty.class);
        if (prop == null) {
            return null;
        }
        return prop.authenticate(item);
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
        
        public List<AuthorizeProjectStrategyDescriptor> getDescriptorsForGlobalSecurityConfigPage() {
            return AuthorizeProjectStrategyDescriptor.getDescriptorsForGlobalSecurityConfigPage();
        }
        
        /**
         * Creates new {@link ProjectQueueItemAuthenticator} from inputs.
         * Additional to that, configure global configurations of {@link AuthorizeProjectStrategy}.
         * 
         * @param req
         * @param formData
         * @return
         * @throws hudson.model.Descriptor.FormException
         * @see hudson.model.Descriptor#newInstance(org.kohsuke.stapler.StaplerRequest, net.sf.json.JSONObject)
         */
        @Override
        public ProjectQueueItemAuthenticator newInstance(StaplerRequest req, JSONObject formData)
                throws FormException
        {
            ProjectQueueItemAuthenticator r = (ProjectQueueItemAuthenticator)super.newInstance(req, formData);
            
            for (AuthorizeProjectStrategyDescriptor d : getDescriptorsForGlobalSecurityConfigPage()) {
                String name = d.getJsonSafeClassName();
                JSONObject js = formData.has(name) ? formData.getJSONObject(name) : new JSONObject();
                d.configureFromGlobalSecurity(req, js);
            }
            
            return r;
        }
    }
    
    /**
     * @return whether Jenkins is configured to use {@link ProjectQueueItemAuthenticator}.
     */
    public static boolean isConfigured() {
        for (QueueItemAuthenticator authenticator: QueueItemAuthenticatorConfiguration.get().getAuthenticators()) {
            if (authenticator instanceof ProjectQueueItemAuthenticator) {
                return true;
            }
        }
        return false;
    }
}
