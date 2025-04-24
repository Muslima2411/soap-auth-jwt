import express from "express";
import { parseString } from "xml2js";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

const PORT = 4000;

const app = express();
app.use(bodyParser.text({ type: "text/xml" }));
app.use(cors());
dotenv.config();

const users = { test: "test123" };

app.post("/soap", (req, res) => {
    parseString(req.body, (err, result) => {
        if (err) {
            res.status(400).send("Error parsing XML");
            return;
        }
        const body = result["soap:Envelope"]["soap:Body"];
        const header = result["soap:Envelope"]["soap:Header"];

        const username = header[0].authToken[0].userName[0];
        const password = header[0].authToken[0].password[0];


        if (body[0].loginRequest) {
          
            if (users[username] !== password) {
                res.status(403).send({ message: "Invalid credentials" });
                return;
            }

            res.status(200).send({ message: "Login successful" });
            return;
        }

        if (body[0].getDataRequest) {
            try {
                const token = jwt.sign({ username, password }, process.env.JWT_SECRET, { expiresIn: '1h' });
                res.send({
                    message: "Request processed successfully",
                    token,
                });
            } catch (error) {
                console.error("JWT Error:", error.message);
                res.status(500).send({ message: "Server error generating token" });
            }
        }
        




    });
});

app.listen(PORT, () => {
    console.log(`server is running on port ${PORT}`);
});