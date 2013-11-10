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

package org.jenkinsci.plugins.authorizeproject.strategy;

import java.io.IOException;

import jenkins.model.Jenkins;
import hudson.Extension;
import hudson.model.Queue;
import hudson.model.User;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.configurationhook.ConfigurationHook;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

/**
 *
 */
public class SpecificUsersAuthorizationStrategy extends AuthorizeProjectStrategy {
    private final String userid;
    
    public String getUserid() {
        return userid;
    }
    
    private final boolean noNeedReauthentication;
    
    public boolean isNoNeedReauthentication() {
        return noNeedReauthentication;
    }
    
    /**
     * No {@link DataBoundConstructor} for requiring to pass the authentication.
     */
    public SpecificUsersAuthorizationStrategy(String userid, boolean noNeedReauthentication) {
        this.userid = userid;
        this.noNeedReauthentication = noNeedReauthentication;
    }
    
    
    /**
     * @param project
     * @param item
     * @return
     * @see org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy#authenticate(hudson.model.AbstractProject, hudson.model.Queue$Item)
     */
    @Override
    public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
        return null;
    }
    
    @Extension
    public static class DescriptorImpl extends Descriptor<AuthorizeProjectStrategy> {
        @Override
        public String getDisplayName() {
            return Messages.SpecificUsersAuthorizationStrategy_DisplayName();
        }
        
        @Override
        public AuthorizeProjectStrategy newInstance(StaplerRequest req, JSONObject formData)
                throws hudson.model.Descriptor.FormException {
            SpecificUsersAuthorizationStrategy strategy = new SpecificUsersAuthorizationStrategy(
                    formData.getString("userid"), 
                    formData.getBoolean("noNeedReauthentication")
            );
            
            SpecificUsersAuthorizationStrategy currentStrategy
                = getCurrentStrategy(req.findAncestorObject(AbstractProject.class));
            
            boolean requireAuthentication = isRequireAuthentication(strategy, currentStrategy);
            
            // TODO
            
            return strategy;
        }
        
        private SpecificUsersAuthorizationStrategy getCurrentStrategy(AbstractProject<?,?> project) {
            if (project == null) {
                return null;
            }
            
            AuthorizeProjectProperty prop = project.getProperty(AuthorizeProjectProperty.class);
            if (prop == null) {
                return null;
            }
            
            if (!(prop.getStrategy() instanceof SpecificUsersAuthorizationStrategy)) {
                return null;
            }
            
            return (SpecificUsersAuthorizationStrategy)prop.getStrategy();
        }
        
        private boolean isRequireAuthentication(
                SpecificUsersAuthorizationStrategy newStrategy,
                SpecificUsersAuthorizationStrategy currentStrategy
        ) {
            if (Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                // Administrator can specify any user.
                return false;
            }
            
            User u = User.current();
            if (u != null && u.getId() != null && u.getId().equals(newStrategy.getUserid())) {
                // Any user can specify oneself.
                return false;
            }
            
            // TODO
            
            return false;
        }
    }
    
    @Extension
    public static class ConfigurationHookImpl extends ConfigurationHook<AbstractProject<?,?>> {
        @Override
        public HookInfo prepareHook(AbstractProject<?, ?> target, StaplerRequest req) {
            Boolean shouldNotHook = (Boolean)req.getSession(true).getAttribute("shouldNotHook");
            if (shouldNotHook != null && shouldNotHook.booleanValue()) {
                return null;
            }
            req.getSession().setAttribute("shouldNotHook", true);
            return new HookInfo("Test for " + target.getFullName());
        }
        
        @Override
        public void doHookSubmit(AbstractProject<?, ?> target, StaplerRequest req)  throws IOException, FormException {
        }
        
        @Override
        public String getTitle(AbstractProject<?, ?> target, StaplerRequest req) {
            // TODO Auto-generated method stub
            return null;
        }
    }
}
