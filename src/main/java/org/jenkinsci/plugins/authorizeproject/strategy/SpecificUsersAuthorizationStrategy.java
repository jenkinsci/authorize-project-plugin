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
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import jenkins.model.Jenkins;
import hudson.Extension;
import hudson.model.Queue;
import hudson.model.User;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;

import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.configurationhook.ConfigurationHook;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

/**
 *
 */
public class SpecificUsersAuthorizationStrategy extends AuthorizeProjectStrategy {
    private static Logger LOGGER = Logger.getLogger(SpecificUsersAuthorizationStrategy.class.getName());
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
        this(userid, noNeedReauthentication, null);
    }
    
    /**
     * No {@link DataBoundConstructor} for requiring to pass the authentication.
     */
    public SpecificUsersAuthorizationStrategy(String userid, boolean noNeedReauthentication, String password) {
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
    
    protected static boolean isAuthenticateionRequired(
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
        
        if (currentStrategy == null) {
            // if currentStrategy is null, authorization is always required.
            return true;
        }
        
        if (
                currentStrategy.isNoNeedReauthentication()
                && currentStrategy.getUserid() != null
                && currentStrategy.getUserid().equals(newStrategy.getUserid())
        ) {
            return false;
        }
        
        return true;
    }
    
    protected static SpecificUsersAuthorizationStrategy getCurrentStrategy(AbstractProject<?,?> project) {
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
    
    @Extension
    public static class DescriptorImpl extends Descriptor<AuthorizeProjectStrategy> {
        @Override
        public String getDisplayName() {
            return Messages.SpecificUsersAuthorizationStrategy_DisplayName();
        }
        
        protected SpecificUsersAuthorizationStrategy newInstanceWithoutAuthentication(
                StaplerRequest req,
                JSONObject formData
        ) throws FormException {
            String userid = formData.getString("userid");
            boolean noNeedReauthentication = formData.getBoolean("noNeedReauthentication");
            
            if (StringUtils.isEmpty(userid)) {
                throw new FormException("userid must be specified", "userid");
            }
            
            return new SpecificUsersAuthorizationStrategy(
                    userid, 
                    noNeedReauthentication
            );
        }
        
        protected boolean authenticate(
                SpecificUsersAuthorizationStrategy strategy, 
                StaplerRequest req,
                JSONObject formData
        ) {
            String password = formData.getString("password");
            if (StringUtils.isEmpty(password)) {
                return false;
            }
            try {
                Jenkins.getInstance().getSecurityRealm().getSecurityComponents().manager.authenticate(
                        new UsernamePasswordAuthenticationToken(strategy.getUserid(), password)
                );
            } catch (AuthenticationException e) {
                LOGGER.log(Level.WARNING, String.format("Failed to authenticate %s", strategy.userid), e);
                return false;
            }
            return true;
        }
        
        @Override
        public SpecificUsersAuthorizationStrategy newInstance(StaplerRequest req, JSONObject formData)
                throws FormException {
            SpecificUsersAuthorizationStrategy strategy = newInstanceWithoutAuthentication(req, formData);
            
            SpecificUsersAuthorizationStrategy currentStrategy
                = getCurrentStrategy(req.findAncestorObject(AbstractProject.class));
            
            if (isAuthenticateionRequired(strategy, currentStrategy)) {
                if (!authenticate(strategy, req, formData)) {
                    throw new FormException("Failed to authenticate", "userid");
                }
            }
            
            return strategy;
        }
    }
    
    @Extension
    public static class ConfigurationHookImpl extends ConfigurationHook<AbstractProject<?,?>> {
        @Override
        public HookInfo prepareHook(AbstractProject<?, ?> target, StaplerRequest req, JSONObject formData) {
            formData = getFormDataFromRoot(formData);
            if (formData == null || formData.isNullObject()) {
                return null;
            }
            if (!formData.has("stapler-class")) {
                return null;
            }
            String staplerClazzName = formData.getString("stapler-class");
            if (staplerClazzName == null) {
                return null;
            }
            try {
                @SuppressWarnings("unchecked")
                Class<? extends AuthorizeProjectStrategy> staplerClass = (Class<? extends AuthorizeProjectStrategy>)Jenkins.getInstance().getPluginManager().uberClassLoader.loadClass(staplerClazzName);
                if (!SpecificUsersAuthorizationStrategy.class.isAssignableFrom(staplerClass)) {
                    return null;
                }
            } catch(ClassNotFoundException e) {
                return null;
            }
            
            DescriptorImpl d = (DescriptorImpl)Jenkins.getInstance().getDescriptor(SpecificUsersAuthorizationStrategy.class);
            SpecificUsersAuthorizationStrategy newStrategy;
            try {
                newStrategy = d.newInstanceWithoutAuthentication(req, formData);
            } catch (FormException e) {
                return null;
            }
            
            if (isAuthenticateionRequired(newStrategy, getCurrentStrategy(target))) {
                if (!d.authenticate(newStrategy, req, formData)) {
                    return new HookInfo(String.format("Password for %s", newStrategy.getUserid()));
                }
            }
            
            return null;
        }
        
        private JSONObject getFormDataFromRoot(JSONObject formData) {
            if (formData == null || formData.isNullObject()) {
                return null;
            }
            
            for (String key: new String[]{
                    "properties",
                    Jenkins.getInstance().getDescriptor(AuthorizeProjectProperty.class).getJsonSafeClassName(),
                    AuthorizeProjectProperty.PROPERTYNAME,
                    "strategy"
            }) {
                formData = formData.getJSONObject(key);
                if (formData == null || formData.isNullObject()) {
                    return null;
                }
            }
            
            return formData;
        }
        
        @Override
        public void onProceeded(StaplerRequest req, StaplerResponse rsp, AbstractProject<?, ?> target, JSONObject formData, JSONObject targetFormData)  throws IOException, FormException {
            String password = formData.getString("password");
            rsp.setContentType("text/javascript");
            rsp.getWriter().println(
                    String.format(
                            "$('specific-users-authorization-strategy-password').setValue('%s');",
                            password
                    )
            );
        }
        
        @Override
        public void onCanceled(StaplerRequest req, StaplerResponse rsp, AbstractProject<?, ?> target, JSONObject formData, JSONObject targetFormData)  throws IOException, FormException {
        }
    }
}
