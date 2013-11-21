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
import hudson.model.Descriptor;
import hudson.model.Queue;
import hudson.model.AbstractProject;

import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;

/**
 *
 */
public class AnonymousAuthorizationStrategy extends AuthorizeProjectStrategy {
    /**
     * @param project
     * @param item
     * @return
     * @see org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy#authenticate(hudson.model.AbstractProject, hudson.model.Queue$Item)
     */
    @Override
    public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
        return Jenkins.ANONYMOUS;
    }
    
    @Extension
    public static class DescriptorImpl extends Descriptor<AuthorizeProjectStrategy> {
        @Override
        public String getDisplayName() {
            return Messages.AnonymousAuthorizationStrategy_DisplayName();
        }
    }
}
