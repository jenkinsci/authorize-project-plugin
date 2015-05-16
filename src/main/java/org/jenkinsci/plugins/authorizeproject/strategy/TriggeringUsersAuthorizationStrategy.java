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

import jenkins.model.Jenkins;
import hudson.Extension;
import hudson.model.Cause;
import hudson.model.Cause.UpstreamCause;
import hudson.model.Cause.UserIdCause;
import hudson.model.Job;
import hudson.model.Queue;
import hudson.model.Run;
import hudson.model.User;
import java.util.Collections;

import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Run builds as a user who triggered the build.
 */
public class TriggeringUsersAuthorizationStrategy extends AuthorizeProjectStrategy {
    /**
     * 
     */
    @DataBoundConstructor
    public TriggeringUsersAuthorizationStrategy() {
    }
    
    /**
     * @param project
     * @param item
     * @return
     * @see org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy#authenticate(hudson.model.Job, hudson.model.Queue.Item)
     */
    @Override
    public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
        Cause.UserIdCause cause = getRootUserIdCause(item);
        if (cause != null) {
            User u = User.get(cause.getUserId(), false, Collections.emptyMap());
            if (u == null) {
                return Jenkins.ANONYMOUS;
            }
            return u.impersonate();
        }
        return null;
    }
    
    /**
     * Returns a cause who triggered this build.
     * 
     * If this is a downstream build, search upstream builds.
     * 
     * @param item
     * @return
     */
    private UserIdCause getRootUserIdCause(Queue.Item item) {
        Run<?,?> upstream = null;
        for (Cause c: item.getCauses()) {
            if (c instanceof UserIdCause) {
                return (UserIdCause)c;
            } else if (c instanceof UpstreamCause) {
                upstream = ((UpstreamCause)c).getUpstreamRun();
            }
        }
        
        while (upstream != null) {
            UserIdCause cause = upstream.getCause(UserIdCause.class);
            if (cause != null) {
                return cause;
            }
            UpstreamCause upstreamCause = upstream.getCause(UpstreamCause.class);
            upstream = (upstreamCause != null)?upstreamCause.getUpstreamRun():null;
        }
        
        return null;
    }
    
    /**
     *
     */
    @Extension
    public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {
        /**
         * @return the name shown in project configuration pages.
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName() {
            return Messages.TriggeringUsersAuthorizationStrategy_DisplayName();
        }
    }
}
