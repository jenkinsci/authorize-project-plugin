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

import jenkins.model.Jenkins;
import jenkins.security.QueueItemAuthenticatorConfiguration;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.model.Queue;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.security.AuthorizationStrategy;

/**
 * Specifies how to authorize its builds.
 */
public class AuthorizeProjectProperty extends JobProperty<AbstractProject<?,?>> {
    /**
     * Property name used for job configuration page.
     */
    public static final String PROPERTYNAME = "authorize_project_property";
    
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
     * Return the authorization for a build.
     * 
     * @param item the item in queue, which will be a build.
     * @return authorization for this build.
     * @see AuthorizeProjectStrategy#authenticate(hudson.model.AbstractProject, hudson.model.Queue.Item)
     */
    public Authentication authenticate(Queue.Item item) {
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
        public DescriptorExtensionList<AuthorizeProjectStrategy, Descriptor<AuthorizeProjectStrategy>> getStrategyList() {
            return AuthorizeProjectStrategy.all();
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
            
            AuthorizeProjectStrategy strategy = bindJSONWithDescriptor(req, form, "strategy", AuthorizeProjectStrategy.class);
            
            return new AuthorizeProjectProperty(strategy);
        }
        
        /**
         * Create a new {@link Describable} object from user inputs.
         * 
         * @param req
         * @param formData
         * @param fieldName
         * @param clazz
         * @return
         * @throws hudson.model.Descriptor.FormException
         */
        private <T extends Describable<?>> T bindJSONWithDescriptor(
                StaplerRequest req,
                JSONObject formData,
                String fieldName,
                Class<T> clazz
        ) throws hudson.model.Descriptor.FormException {
            formData = formData.getJSONObject(fieldName);
            if (formData == null || formData.isNullObject()) {
                return null;
            }
            if (!formData.has("stapler-class")) {
                throw new FormException("No stapler-class is specified", fieldName);
            }
            String staplerClazzName = formData.getString("stapler-class");
            if (staplerClazzName == null) {
                throw new FormException("No stapler-class is specified", fieldName);
            }
            try {
                @SuppressWarnings("unchecked")
                Class<? extends T> staplerClass = (Class<? extends T>)Jenkins.getInstance().getPluginManager().uberClassLoader.loadClass(staplerClazzName);
                Descriptor<?> d = Jenkins.getInstance().getDescriptorOrDie(staplerClass);
                
                @SuppressWarnings("unchecked")
                T instance = (T)d.newInstance(req, formData);
                
                return instance;
            } catch(ClassNotFoundException e) {
                throw new FormException(
                        String.format("Failed to instantiate %s", staplerClazzName),
                        e,
                        fieldName
                );
            }
        }
    }
}
