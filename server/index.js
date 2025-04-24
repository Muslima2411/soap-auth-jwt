import express from "express";
import { Builder, parseString } from "xml2js";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

const PORT = 4000;

const app = express();
app.use(bodyParser.text({ type: "text/xml" }));
app.use(cors());
dotenv.config();

const users = { test: "test123", test1: "test1234", test2: "test12345" };

const myData = {
    protectedData: users,
};

const soapResponseBuilder = (data, operation) => {
    const builder = new Builder({ headless: true });

    const soapStructure = {
        "soap:Envelope": {
            $: {
                "xmlns:soap": "http://schemas.xmlsoap.org/soap/envelope/",
            },
            "soap:Body": {},
        },
    };

    if (operation === "loginResponse") {
        soapStructure["soap:Envelope"]["soap:Body"]["loginResponse"] = {
            token: [data],
        };
    }
    else if (operation === "getDataResponse") {
        soapStructure["soap:Envelope"]["soap:Body"]["getDataResponse"] = {
            data: [JSON.stringify(data)],
        };
    }
    
    return builder.buildObject(soapStructure);
};

const soapFaultResponseBuilder = (error) => {
    const builder = new Builder({ headless: true });
    const soapStructure = {
        "soap:Envelope": {
            $: {
                "xmlns:soap": "http://schemas.xmlsoap.org/soap/envelope/",
            },
            "soap:Fault": {
                faultcode: ["soap:Server"],
                faultstring: [error],
            },
        },
    };

    return builder.buildObject(soapStructure);
};

app.post("/soap", (req, res) => {
    parseString(req.body, (err, result) => {
        if (err) {
            res.status(400).send(soapFaultResponseBuilder("Error parsing XML"));
            return;
        }
        const body = result["soap:Envelope"]["soap:Body"];
        const header = result["soap:Envelope"]["soap:Header"];

        if (body[0].loginRequest) {
            if (!header || !header[0]?.authToken) {
                console.warn("[/soap] Missing authentication token");
                res.status(400).send(soapFaultResponseBuilder("Missing authentication token"));
                return;
            }

            const username = header[0].authToken[0].userName[0];
            const password = header[0].authToken[0].password[0];

            if (users[username] !== password) {
                console.warn("Invalid credentials");
                res.status(403).send(soapFaultResponseBuilder("Invalid credentials"));
                return;
            }
            const token = jwt.sign({ username, password }, process.env.JWT_SECRET, { expiresIn: "1h" });
            res.send(soapResponseBuilder(token, "loginResponse"));
        }

        else if (body[0].getDataRequest) {
            const token = header[0]?.authToken[0]?.token[0];
            if (!token) {
                res.status(401).send(soapFaultResponseBuilder("Missing token"));
                return;
            }
            try{
                const response = jwt.verify(token, process.env.JWT_SECRET);
                res.send(soapResponseBuilder(myData, "getDataResponse"));
            }
            catch (error) {
                res.status(403).send(soapFaultResponseBuilder("Invalid token"));
                return;
            }

        }else {
            res.status(400).send(soapFaultResponseBuilder("Invalid SOAP request"));
        }
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
