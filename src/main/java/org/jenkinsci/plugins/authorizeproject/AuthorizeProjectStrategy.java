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

import org.acegisecurity.Authentication;

import jenkins.model.Jenkins;
import hudson.DescriptorExtensionList;
import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Queue;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;

/**
 * Extension point to define a new strategy to authorize builds configured in project configuration pages.
 */
public abstract class AuthorizeProjectStrategy extends AbstractDescribableImpl<AuthorizeProjectStrategy>
        implements ExtensionPoint {
    /**
     * @return all the registered {@link AuthorizeProjectStrategy}.
     */
    public static DescriptorExtensionList<AuthorizeProjectStrategy, Descriptor<AuthorizeProjectStrategy>> all() {
        return Jenkins.getInstance().getDescriptorList(AuthorizeProjectStrategy.class);
    }
    
    /**
     * Returns the {@link Authentication} for the build.
     * 
     * @param project the project to run.
     * @param item the item in queue, which will be a build.
     * @return
     */
    public abstract Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item);
}
