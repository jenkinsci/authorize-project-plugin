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

package org.jenkinsci.plugins.configurationhook;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;

import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import hudson.ExtensionPoint;
import hudson.model.Describable;
import hudson.model.Descriptor;

/**
 *
 */
public abstract class ConfigurationHook<T> extends Descriptor<ConfigurationHook<T>> implements Describable<ConfigurationHook<T>>, ExtensionPoint {
    public abstract HookInfo prepareHook(T target, StaplerRequest req, JSONObject formData);
    public abstract void onProceeded(StaplerRequest req, StaplerResponse rsp, T target, JSONObject formData, JSONObject targetFormData) throws IOException, FormException;
    public abstract void onCanceled(StaplerRequest req, StaplerResponse rsp, T target, JSONObject formData, JSONObject targetFormData) throws IOException, FormException;
    
    private static final Logger LOGGER = Logger.getLogger(ConfigurationHook.class.getName());
    private final Class<T> targetType;
    
    @SuppressWarnings("unchecked")
    protected ConfigurationHook() {
        super(self());
        targetType = calcTargetType();
    }
    
    @Override
    public String getDisplayName() {
        return "";
    }
    
    @SuppressWarnings("unchecked")
    public HookInfo prepareHookRaw(Object target, StaplerRequest req) {
        JSONObject formData = null;
        try {
            formData = req.getSubmittedForm();
        } catch (ServletException e) {
            LOGGER.log(Level.WARNING, "Failed to extract submitted form", e);
        }
        return prepareHook((T)target, req, formData);
    }
    
    public Descriptor<ConfigurationHook<T>> getDescriptor() {
        return this;
    }
    
    public String getPopupId() {
        return getClass().getName().replace("_", "--").replace(".", "-");
    }
    
    @SuppressWarnings("unchecked")
    protected Class<T> calcTargetType() {
        Class<? extends ConfigurationHook<T>> clazz = (Class<? extends ConfigurationHook<T>>)getClass();
        while(clazz != null) {
            Type directGenericSuperclass = clazz.getGenericSuperclass();
            if (directGenericSuperclass != null) {
                if (directGenericSuperclass instanceof ParameterizedType) {
                    if (ConfigurationHook.class.equals(((ParameterizedType)directGenericSuperclass).getRawType())) {
                        Type type = ((ParameterizedType)directGenericSuperclass).getActualTypeArguments()[0];
                        if (type instanceof ParameterizedType) {
                            type = ((ParameterizedType)type).getRawType();
                        }
                        return (Class<T>)type;
                    }
                }
            }
            
            Class<?> superClazz = clazz.getSuperclass();
            if (!ConfigurationHook.class.isAssignableFrom(superClazz)) {
                // this never happen.
                return null;
            }
            
            clazz = (Class<? extends ConfigurationHook<T>>)superClazz;
        }
        
        return null;
    }
    
    public Class<T> getTargetType() {
        return targetType;
    }
    
    public void doHookSubmit(StaplerRequest req, StaplerResponse rsp) throws IOException, FormException {
        T target = req.findAncestorObject(getTargetType());
        JSONObject formData;
        JSONObject targetFormData;
        try {
            formData = req.getSubmittedForm();
        } catch (ServletException e) {
            throw new FormException(e, "json");
        }
        try {
            targetFormData = JSONObject.fromObject(req.getParameter("targetJson"));
        } catch (JSONException e) {
            throw new FormException(e, "targetJson");
        }
        
        if ("cancel".equals(req.getParameter("command"))) {
            onCanceled(req, rsp, target, formData, targetFormData);
        } else {
            onProceeded(req, rsp, target, formData, targetFormData);
        }
    }
    
    public String getHookSubmitUrl(StaplerRequest req) {
        return String.format("%s/%s/%s", getCurrentDescriptorByNameUrl(), getDescriptorUrl(), "hookSubmit");
    }
    
    public static class HookInfo {
        private final String title;
        public String getTitle() {
            return title;
        }
        
        public HookInfo() {
            this("");
        }
        
        public HookInfo(String title) {
            this.title = title;
        }
    }
}
