package com.example;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Repository {

    @JsonProperty("id")
    long id;

    @JsonProperty("owner")
    GithubUser User;

    @JsonProperty("name")
    String name;

    @JsonProperty("full_name")
    String fullName;

    @JsonProperty("description")
    String description;

    @JsonProperty("html_url")
    String url;

    @Override
    public String toString() {
        return "Repository " + id + ": " + name + "\n" + url + "\n" + description + "\n";
    }
}
