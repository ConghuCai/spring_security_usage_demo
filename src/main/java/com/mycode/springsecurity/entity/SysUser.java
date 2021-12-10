package com.mycode.springsecurity.entity;

public class SysUser {
    private Integer id;

    private String account;

    private String userName;

    private String password;

    private String lastLoginTime;

    private Boolean enabled;

    private Boolean notExpired;

    private Boolean accountNotLocked;

    private Boolean credentialsNotExpired;

    private String createTime;

    private String updateTime;

    private Integer createUser;

    private Integer updateUser;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getAccount() {
        return account;
    }

    public void setAccount(String account) {
        this.account = account;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getLastLoginTime() {
        return lastLoginTime;
    }

    public void setLastLoginTime(String lastLoginTime) {
        this.lastLoginTime = lastLoginTime;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean getNotExpired() {
        return notExpired;
    }

    public void setNotExpired(Boolean notExpired) {
        this.notExpired = notExpired;
    }

    public Boolean getAccountNotLocked() {
        return accountNotLocked;
    }

    public void setAccountNotLocked(Boolean accountNotLocked) {
        this.accountNotLocked = accountNotLocked;
    }

    public Boolean getCredentialsNotExpired() {
        return credentialsNotExpired;
    }

    public void setCredentialsNotExpired(Boolean credentialsNotExpired) {
        this.credentialsNotExpired = credentialsNotExpired;
    }

    public String getCreateTime() {
        return createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public String getUpdateTime() {
        return updateTime;
    }

    public void setUpdateTime(String updateTime) {
        this.updateTime = updateTime;
    }

    public Integer getCreateUser() {
        return createUser;
    }

    public void setCreateUser(Integer createUser) {
        this.createUser = createUser;
    }

    public Integer getUpdateUser() {
        return updateUser;
    }

    public void setUpdateUser(Integer updateUser) {
        this.updateUser = updateUser;
    }
}