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

import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.Queue;

import javax.annotation.CheckForNull;

import org.acegisecurity.Authentication;
import org.kohsuke.stapler.DataBoundConstructor;

import jenkins.security.QueueItemAuthenticatorDescriptor;
import jenkins.security.QueueItemAuthenticator;

/**
 * Authorize builds of projects configured with {@link AuthorizeProjectProperty}.
 */
public class ProjectQueueItemAuthenticator extends QueueItemAuthenticator {
    /**
     * 
     */
    @DataBoundConstructor
    public ProjectQueueItemAuthenticator() {
    }
    
    /**
     * @param item
     * @return
     * @see jenkins.security.QueueItemAuthenticator#authenticate(hudson.model.Queue.Item)
     */
    @Override
    @CheckForNull
    public Authentication authenticate(Queue.Item item) {
        if (!(item.task instanceof AbstractProject)) {
            // This handles only AbstractProject.
            return null;
        }
        AbstractProject<?, ?> project = (AbstractProject<?,?>)item.task;
        AuthorizeProjectProperty prop = project.getProperty(AuthorizeProjectProperty.class);
        if (prop == null) {
            return null;
        }
        return prop.authenticate(item);
    }
    
    /**
     *
     */
    @Extension
    public static class DescriptorImpl extends QueueItemAuthenticatorDescriptor {
        /**
         * @return the name shown in the security configuration page.
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName() {
            return Messages.ProjectQueueItemAuthenticator_DisplayName();
        }
    }
}
