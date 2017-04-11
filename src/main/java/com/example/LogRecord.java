package com.example;


import java.util.Date;

public class LogRecord {

    public enum Type {logout, login}

    public String login;
    public Type type;
    public String date;

    public LogRecord(String login, Date date, Type type) {
        this.login = login;
        this.date = date.toString();
        this.type = type;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }



    public String getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date.toString();
    }


    public LogRecord() {
        this.login = "generic";
        this.date = new Date().toString();
        this.type = Type.login;
    }

    @Override
    public String toString() {
        return "Login: " + login + " at " + date + " " + type;
    }


}
