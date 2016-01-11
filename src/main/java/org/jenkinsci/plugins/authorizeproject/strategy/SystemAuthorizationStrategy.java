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

import hudson.Extension;
import hudson.model.Job;
import hudson.model.Queue;
import hudson.security.ACL;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategyDescriptor;
import org.jenkinsci.plugins.authorizeproject.GlobalQueueItemAuthenticator;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Run builds as {@link ACL#SYSTEM}. Using this strategy becomes important when {@link GlobalQueueItemAuthenticator}
 * is forcing jobs to a user other than {@link ACL#SYSTEM}.
 *
 * @since 1.1.1
 */
public class SystemAuthorizationStrategy extends AuthorizeProjectStrategy {
    @DataBoundConstructor
    public SystemAuthorizationStrategy() {
    }

    /**
     * Authorize builds as {@link ACL#SYSTEM}.
     *
     * @param project
     * @param item
     * @return anonymous authorization
     * @see AuthorizeProjectStrategy#authenticate(Job, Queue.Item)
     */
    @Override
    public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
        return ACL.SYSTEM;
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
            return Messages.SystemAuthorizationStrategy_DisplayName();
        }

        @Override
        public boolean isEnabledByDefault() {
            return false;
        }
    }
}
