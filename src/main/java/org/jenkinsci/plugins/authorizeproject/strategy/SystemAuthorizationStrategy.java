/*
 * The MIT License
 * 
 * Copyright (c) 2013-2016 Stephen Connolly, IKEDA Yasuyuki
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

package org.jenkinsci.plugins.authorizeproject.strategy;

import hudson.Extension;
import hudson.model.Job;
import hudson.model.Queue;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategyDescriptor;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Run builds as {@link ACL#SYSTEM}. Using this strategy becomes important when
 * {@link org.jenkinsci.plugins.authorizeproject.GlobalQueueItemAuthenticator}
 * is forcing jobs to a user other than {@link ACL#SYSTEM}.
 *
 * @since 1.2.0
 */
public class SystemAuthorizationStrategy extends AuthorizeProjectStrategy {

    @DataBoundConstructor
    public SystemAuthorizationStrategy() {
        checkAuthorizationConfigurePermission(Jenkins.get());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication authenticate(Job<?, ?> job, Queue.Item item) {
        return ACL.SYSTEM;
    }

    /**
     * Return {@link SystemAuthorizationStrategy} configured in a job.
     *
     * @param job the {@link Job}
     * @return the {@link SystemAuthorizationStrategy} or {@code null}
     */
    protected static SystemAuthorizationStrategy getCurrentStrategy(Job<?, ?> job) {
        if (job == null) {
            return null;
        }

        AuthorizeProjectProperty prop = job.getProperty(AuthorizeProjectProperty.class);
        if (prop == null) {
            return null;
        }

        AuthorizeProjectStrategy strategy = prop.getStrategy();
        if (!(strategy instanceof SystemAuthorizationStrategy)) {
            return null;
        }

        return (SystemAuthorizationStrategy) strategy;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasJobConfigurePermission(AccessControlled context) {
        return context.hasPermission(Jenkins.ADMINISTER) || getDescriptor().isPermitReconfiguration();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasAuthorizationConfigurePermission(AccessControlled context) {
        return context.hasPermission(Jenkins.RUN_SCRIPTS);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    /**
     * Our descriptor
     */
    @Extension(ordinal = -100)
    public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {

        /**
         * Flag to mark where changing a job using this strategy requires administrator permissions.
         */
        private boolean permitReconfiguration;

        /**
         * @return the name shown in project configuration pages.
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName() {
            return Messages.SystemAuthorizationStrategy_DisplayName();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isEnabledByDefault() {
            return false;
        }

        /**
         * Gets the flag to mark where changing a job using this strategy requires administrator permissions.
         *
         * @return {@code true} if non-admins are allowed to modify jobs that are using this strategy.
         */
        public boolean isPermitReconfiguration() {
            return permitReconfiguration;
        }

        /**
         * Sets the flag to mark where changing a job using this strategy requires administrator permissions.
         *
         * @param permitReconfiguration {@code true} if non-admins are allowed to modify jobs that are using this strategy.
         */
        public void setPermitReconfiguration(boolean permitReconfiguration) {
            if (permitReconfiguration != this.permitReconfiguration) {
                this.permitReconfiguration = permitReconfiguration;
                save();
            }
        }

        /**
         * Tests if an object is a {@link Job}
         *
         * @param it the object.
         * @return {@code true} if and only if the supplied object is a {@link Job}
         */
        @Restricted(NoExternalUse.class) // helper method for Jelly EL
        public boolean isJob(Object it) {
            return it instanceof Job;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void configureFromGlobalSecurity(StaplerRequest req, JSONObject js) throws FormException {
            setPermitReconfiguration(js.getBoolean("permitReconfiguration"));
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public SystemAuthorizationStrategy newInstance(StaplerRequest req, JSONObject formData)
                throws FormException {
            SystemAuthorizationStrategy result = (SystemAuthorizationStrategy) super.newInstance(req, formData);
            Jenkins instance = Jenkins.get();
            if (!instance.hasPermission(Jenkins.RUN_SCRIPTS)) {
                Job job = req.findAncestorObject(Job.class);
                if (job != null) {
                    if (!(permitReconfiguration && getCurrentStrategy(job) != null)) {
                        throw new FormException(Messages.SystemAuthorizationStrategy_administersOnly(), "strategy");
                    }
                }
            }
            return result;
        }

        public FormValidation doCheckPermitReconfiguration(@QueryParameter boolean value) {
            if (!value) {
                return FormValidation.warning(Messages.SystemAuthorizationStrategy_administersOnly());
            }
            return FormValidation.warning(Messages.SystemAuthorizationStrategy_userConfigurable());
        }
    }
}
