package com.example.securitydemo.jwt;


public class LoginRequest {
    private String userName;
    private String password;

    public void setPassword(String password) {
        this.password = password;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }


    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }



}
