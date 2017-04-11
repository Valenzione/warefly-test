package com.example;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GithubUser {

    @JsonProperty("login")
    String login;

    @JsonProperty("id")
    long id;

    @JsonProperty("public_repos")
    int publicRepos;

    @Override
    public String toString() {
        return login + " " + id + " " + publicRepos;
    }
}
