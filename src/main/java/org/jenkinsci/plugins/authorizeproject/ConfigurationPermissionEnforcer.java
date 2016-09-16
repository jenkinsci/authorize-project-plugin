package org.jenkinsci.plugins.authorizeproject;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

/**
 * @author Stephen Connolly
 */
public class ConfigurationPermissionEnforcer extends JobProperty<Job<?,?>> {
    @DataBoundConstructor
    public ConfigurationPermissionEnforcer() {
    }

    @Extension(ordinal = Double.MAX_VALUE)
    public static class DescriptorImpl extends JobPropertyDescriptor {

        @Override
        public String getDisplayName() {
            return "ConfigurationPermissionEnforcer";
        }

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
            return null;
        }
    }
}
