import { Request, Router } from 'express'
import { Strategy, } from 'passport-strategy'
import { initProvider } from './utils'
import { PROVIDERS } from '@shared/config'
import Boom from '@hapi/boom'

import fetch from 'node-fetch';


const otpStore = {} as any

const deliver = async (baseUrl: string, phoneNumber: string, otp: string) => {
    console.log("Sending", phoneNumber, otp)
    const response = await fetch(baseUrl, {
        method: 'POST', body:
            JSON.stringify({
                phoneNumber,
                otp
            }),
        headers: { 'Content-Type': 'application/json' }
    });
    const json = await response.json();

    return json.status == "success"
}

class PasswordlessStrategy implements Strategy {
    options: any;
    verify: any
    success: any;
    fail: any;
    name = "passwordless"
    error: any;
    redirect: any;
    pass: any;
    constructor(options: any, verify: any) {
        this.options = options
        console.log('S', this.options)
        this.verify = verify
        // OAuth2Strategy.call(this as OAuth2Strategy, options, verify);
    }

    authenticate(req: Request, options?: any) {
        const DELIVER_BASE_URL = this.options.deliverBaseUrl
        const EXPIRE_DURATION = this.options.expireDuration * 1000 // Convert to millis
        const RESEND_DURATION = this.options.resendDuration * 1000 // Convert to millis
        const FIXED_OTP = this.options.fixedOtp
        console.log("COnfiguration ", DELIVER_BASE_URL, EXPIRE_DURATION, RESEND_DURATION)

        const { phoneNumber, otp } = req.query as { phoneNumber: string, otp: string }
        console.log(phoneNumber, otp, otpStore[phoneNumber], "----")
        const savedOtpState = otpStore[phoneNumber]
        if (!phoneNumber) {
            throw Boom.badRequest("Invalid phone number")
        }
        else if (!otp && savedOtpState && savedOtpState.createdTime > Date.now() - RESEND_DURATION) {
            throw Boom.badRequest("Too Early to resend OTP")
        }
        else if (!otp) {
            const newOtp = FIXED_OTP || `${Math.floor(1000 + Math.random() * 9000)}`
            otpStore[phoneNumber] = { otp: newOtp, createdTime: Date.now() }
            console.log("New otp", newOtp)
            return deliver(DELIVER_BASE_URL, phoneNumber, newOtp).then((success: boolean) => {
                if (success) {

                    return this.redirect('/healthz')
                }
                else {
                    throw Boom.serverUnavailable("Failed to send OTP")
                }
            }).catch(() => {
                return this.redirect('/healthz?sent=false')
            })
        }
        else if (!savedOtpState || savedOtpState.createdTime < Date.now() - EXPIRE_DURATION) {
            delete otpStore[phoneNumber]
            throw Boom.badRequest("Invalid Request")
        }
        else if (savedOtpState.otp != otp) {
            throw Boom.badRequest("Invalid OTP")
        } else {
            this.verify(req, "", "", { id: phoneNumber }, (error: any, user: any) => { // Refresh token and 
                console.log("Got the user", JSON.stringify(user))
                this.success(user, {})
            })
            delete otpStore[phoneNumber]
        }

    }
}

export default (router: Router): void => {
    const options = PROVIDERS.passwordless
    console.log("Starting options", options)
    // Checks if the strategy is enabled. Don't create any route otherwise
    if (options) {
        // Checks if the strategy has at least a client ID and a client secret
        // if (!options.clientID || !options.clientSecret) {
        //     throw Boom.badImplementation(`Missing environment variables for Google OAuth.`)
        // }
        initProvider(router, 'passwordless', PasswordlessStrategy, { scope: [] })
    }
}
