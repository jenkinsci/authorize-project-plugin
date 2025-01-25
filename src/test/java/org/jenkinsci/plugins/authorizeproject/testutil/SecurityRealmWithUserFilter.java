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

package org.jenkinsci.plugins.authorizeproject.testutil;

import hudson.security.SecurityRealm;
import java.util.List;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Wraps other {@link SecurityRealm},
 * and throws {@link UsernameNotFoundException} for unknown users.
 * <p>
 * Expected to be used with {@link JenkinsRule#createDummySecurityRealm()}
 */
public class SecurityRealmWithUserFilter extends SecurityRealm {
    private final SecurityRealm baseSecurityRealm;
    private final List<String> validUserList;

    public SecurityRealmWithUserFilter(SecurityRealm baseSecurityRealm, List<String> validUserList) {
        this.baseSecurityRealm = baseSecurityRealm;
        this.validUserList = validUserList;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        final SecurityComponents baseComponent = baseSecurityRealm.createSecurityComponents();
        return new SecurityComponents(
                baseComponent.manager2,
                username -> {
                    if (!validUserList.contains(username)) {
                        throw new UsernameNotFoundException(
                                String.format("%s is not listed as valid username.", username));
                    }
                    return baseComponent.userDetails2.loadUserByUsername(username);
                },
                baseComponent.rememberMe2);
    }
}
