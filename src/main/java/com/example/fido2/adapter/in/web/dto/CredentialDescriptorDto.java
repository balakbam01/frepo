package com.example.fido2.adapter.in.web.dto;

import java.util.List;

/** Wire representation of a PublicKeyCredentialDescriptor sent to the browser. */
public class CredentialDescriptorDto {

    private String type = "public-key";
    private String id;
    private List<String> transports;

    public CredentialDescriptorDto() {}

    public CredentialDescriptorDto(String id, List<String> transports) {
        this.id = id;
        this.transports = transports;
    }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public List<String> getTransports() { return transports; }
    public void setTransports(List<String> transports) { this.transports = transports; }
}
