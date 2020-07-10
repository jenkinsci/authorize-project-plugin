package org.jenkinsci.plugins.authorizeproject;

import hudson.Extension;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.security.AccessControlled;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

import javax.annotation.CheckForNull;

import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

/**
 * A dummy {@link JobProperty} responsible for providing the {@link AuthorizeProjectStrategy} with a veto over job
 * reconfiguration.
 *
 * @since 1.3.0
 */
@Restricted(NoExternalUse.class) // TODO remove this class once a fix for JENKINS-38219 is available in baseline core
public class ConfigurationPermissionEnforcer extends JobProperty<Job<?,?>> {
    /**
     * Our constructor.
     */
    @DataBoundConstructor
    public ConfigurationPermissionEnforcer() {
    }

    /**
     * Extension to perform the restriction.
     */
    @Extension(ordinal = Double.MAX_VALUE) // require this high value to apply the veto as early as possible
    @Restricted(NoExternalUse.class)
    public static class DescriptorImpl extends JobPropertyDescriptor {

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return "ConfigurationPermissionEnforcer";
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public JobProperty<?> newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            Job<?,?> job = req.findAncestorObject(Job.class);
            AccessControlled context = req.findAncestorObject(AccessControlled.class);
            checkConfigurePermission(job, context);
            // we don't actually return a job property... just want to be called on every form submission.
            return null;
        }

        private void checkConfigurePermission(@CheckForNull Job<?, ?> job, @CheckForNull AccessControlled context) {
            if (job == null) {
                return;
            }
            if (context == null) {
                // this should not happen.
                context = job;
            }
            if (Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                // allows any configurations by system administrators.
                // It may not be allowed even if the user is an administrator of the job,
                // 
                return;
            }
            AuthorizeProjectProperty property = job.getProperty(AuthorizeProjectProperty.class);
            if (property == null) {
                return;
            }
            if (!ProjectQueueItemAuthenticator.isConfigured()) {
                return;
            }
            AuthorizeProjectStrategy strategy = property.getStrategy();
            if (strategy == null) {
                return;
            }
            strategy.checkJobConfigurePermission(context);
        }
    }
}
