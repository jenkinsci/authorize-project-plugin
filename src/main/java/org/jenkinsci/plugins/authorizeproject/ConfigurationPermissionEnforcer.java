package org.jenkinsci.plugins.authorizeproject;

import hudson.Extension;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import net.sf.json.JSONObject;
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
            if (job != null) {
                AuthorizeProjectProperty property = job.getProperty(AuthorizeProjectProperty.class);
                if (property != null && ProjectQueueItemAuthenticator.isConfigured()) {
                    AuthorizeProjectStrategy strategy = property.getStrategy();
                    if (strategy != null) {
                        strategy.checkConfigurePermission(job);
                    }
                }
            }
            // we don't actually return a job property... just want to be called on every form submission.
            return null;
        }
    }
}
