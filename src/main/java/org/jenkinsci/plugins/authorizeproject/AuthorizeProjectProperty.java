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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import jenkins.security.QueueItemAuthenticatorConfiguration;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.model.DescriptorVisibilityFilter;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.model.Queue;
import hudson.model.Descriptor;

/**
 * Specifies how to authorize its builds.
 */
public class AuthorizeProjectProperty extends JobProperty<Job<?,?>> {
    /**
     * Property name used for job configuration page.
     */
    public static final String PROPERTYNAME = "authorize_project_property";
    
    private static final Logger LOGGER = Logger.getLogger(AuthorizeProjectProperty.class.getName());
    
    private AuthorizeProjectStrategy strategy;
    
    /**
     * @return
     */
    public AuthorizeProjectStrategy getStrategy() {
        return strategy;
    }
    
    /**
     * Create a new instance.
     * 
     * Not annotated with {@link DataBoundConstructor} for instantiating
     * explicitly in {@link DescriptorImpl#newInstance(StaplerRequest, JSONObject)}.
     * It is required to call newInstance of {@link AuthorizeProjectProperty}.
     * 
     * @param strategy
     */
    public AuthorizeProjectProperty(AuthorizeProjectStrategy strategy) {
        this.strategy = strategy;
    }
    
    /**
     * @return strategy only when it's enabled. null otherwise.
     */
    public AuthorizeProjectStrategy getEnabledStrategy() {
        AuthorizeProjectStrategy strategy = getStrategy();
        if(strategy == null) {
            return null;
        }
        if(DescriptorVisibilityFilter.apply(
                ProjectQueueItemAuthenticator.getConfigured(),
                Arrays.asList(strategy.getDescriptor())
        ).isEmpty()) {
            LOGGER.log(
                    Level.WARNING,
                    "{0} is configured but disabled in the globel-security configuration.",
                    strategy.getDescriptor().getDisplayName()
            );
            return null;
        }
        return strategy;
    }
    
    /**
     * Return the authorization for a build.
     * 
     * @param item the item in queue, which will be a build.
     * @return authorization for this build.
     * @see AuthorizeProjectStrategy#authenticate(hudson.model.Job, hudson.model.Queue.Item)
     */
    public Authentication authenticate(Queue.Item item) {
        AuthorizeProjectStrategy strategy = getEnabledStrategy();
        if (strategy == null) {
            return null;
        }
        return strategy.authenticate(owner, item);
    }
    
    /**
     * Descriptor for {@link AuthorizeProjectProperty}.
     * 
     * Provides functions for displaying.
     */
    @Extension
    public static class DescriptorImpl extends JobPropertyDescriptor {
        /**
         * @return the name shown in the project configuration page.
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName() {
            return Messages.AuthorizeProjectProperty_DisplayName();
        }
        
        /**
         * Enabled only when {@link ProjectQueueItemAuthenticator} is configured.
         * 
         * @param jobType
         * @return
         * @see hudson.model.JobPropertyDescriptor#isApplicable(java.lang.Class)
         */
        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends Job> jobType) {
            return ProjectQueueItemAuthenticator.isConfigured();
        }
        
        /**
         * Returns the property name to hold configuration of {@link AuthorizeProjectProperty}
         * 
         * @return the property name
         */
        public String getPropertyName() {
            return PROPERTYNAME;
        }
        
        /**
         * @return all the registered {@link AuthorizeProjectStrategy}.
         */
        @Deprecated
        public DescriptorExtensionList<AuthorizeProjectStrategy, Descriptor<AuthorizeProjectStrategy>> getStrategyList() {
            return AuthorizeProjectStrategy.all();
        }
        
        /**
         * @return enabled {@link AuthorizeProjectStrategy}, empty if authorize-project is not enabled.
         */
        public List<Descriptor<AuthorizeProjectStrategy>> getEnabledAuthorizeProjectStrategyDescriptorList() {
            ProjectQueueItemAuthenticator authenticator = ProjectQueueItemAuthenticator.getConfigured();
            if (authenticator == null) {
                return Collections.emptyList();
            }
            return DescriptorVisibilityFilter.apply(authenticator, AuthorizeProjectStrategy.all());
        }
        
        /**
         * Create a new {@link AuthorizeProjectProperty} from user inputs.
         * 
         * @param req
         * @param formData
         * @return
         * @throws hudson.model.Descriptor.FormException
         * @see hudson.model.JobPropertyDescriptor#newInstance(org.kohsuke.stapler.StaplerRequest, net.sf.json.JSONObject)
         */
        @Override
        public AuthorizeProjectProperty newInstance(StaplerRequest req, JSONObject formData)
                throws hudson.model.Descriptor.FormException {
            if(formData == null || formData.isNullObject()) {
                return null;
            }
            JSONObject form = formData.getJSONObject(getPropertyName());
            if(form == null || form.isNullObject()) {
                return null;
            }
            
            AuthorizeProjectStrategy strategy = AuthorizeProjectUtil.bindJSONWithDescriptor(req, form, "strategy", AuthorizeProjectStrategy.class);
            
            return new AuthorizeProjectProperty(strategy);
        }
    }
}
