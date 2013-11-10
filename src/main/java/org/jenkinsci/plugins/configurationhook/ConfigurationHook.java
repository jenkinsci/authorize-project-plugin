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

import org.kohsuke.stapler.StaplerRequest;

import hudson.ExtensionPoint;
import hudson.model.Describable;
import hudson.model.Descriptor;

/**
 *
 */
public abstract class ConfigurationHook<T> extends Descriptor<ConfigurationHook<T>> implements Describable<ConfigurationHook<T>>, ExtensionPoint {
    public abstract void doHookSubmit(T target, StaplerRequest req) throws IOException, FormException;
    public abstract String getTitle(T target, StaplerRequest req);
    public abstract HookInfo prepareHook(T target, StaplerRequest req);
    
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
        return prepareHook((T)target, req);
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
    
    public String getTitle(StaplerRequest req) {
        return getTitle(req.findAncestorObject(getTargetType()), req);
    }
    
    public void doHookSubmit(StaplerRequest req) throws IOException, FormException {
        // TODO: prepare some mechanism to handle response.
        doHookSubmit(req.findAncestorObject(getTargetType()), req);
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
