/*
 * The MIT License
 * 
 * Copyright (c) 2016 IKEDA Yasuyuki
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

import jenkins.model.Jenkins;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import net.sf.json.JSONObject;

import org.kohsuke.stapler.StaplerRequest;

/**
 *
 */
public class AuthorizeProjectUtil {
    /**
     * Create a new {@link Describable} object from user inputs.
     * 
     * @param req
     * @param formData
     * @param fieldName
     * @param clazz
     * @return
     * @throws FormException
     */
    public static <T extends Describable<?>> T bindJSONWithDescriptor(
            StaplerRequest req,
            JSONObject formData,
            String fieldName,
            Class<T> clazz
    ) throws FormException {
        formData = formData.getJSONObject(fieldName);
        if (formData == null || formData.isNullObject()) {
            return null;
        }
        String staplerClazzName = formData.optString("$class", null);
        if (staplerClazzName == null) {
          // Fall back on the legacy stapler-class attribute.
          staplerClazzName = formData.optString("stapler-class", null);
        }
        if (staplerClazzName == null) {
            throw new FormException("No $class is specified", fieldName);
        }
        try {
            @SuppressWarnings("unchecked")
            Class<? extends T> staplerClass = (Class<? extends T>)Jenkins.getInstance().getPluginManager().uberClassLoader.loadClass(staplerClazzName);
            Descriptor<?> d = Jenkins.getInstance().getDescriptorOrDie(staplerClass);
            
            @SuppressWarnings("unchecked")
            T instance = (T)d.newInstance(req, formData);
            
            return instance;
        } catch(ClassNotFoundException e) {
            throw new FormException(
                    String.format("Failed to instantiate %s", staplerClazzName),
                    e,
                    fieldName
            );
        }
    }
    
    public static boolean userIdEquals(String a, String b) {
        // TODO use Jenkins.getInstance().getSecurityRealm().getUserIdStrategy().equals() once Jenkins 1.566+
        return a.equals(b);
    }
}
