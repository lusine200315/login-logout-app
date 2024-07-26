"use server"

import { OptionalUser } from "./types"
import { nanoid } from "nanoid"
import bcrypt from 'bcrypt'
import { addUser, getAllUsers, getUserByLogin, updateUserInDb } from "./api"
import { redirect } from "next/navigation"
import { createAuthSession, destroySession } from "./auth"

export const handleSignup = async (prev:unknown, data:FormData) => {

    if(!data.get('name') || !data.get('surname')){
        return  {
            message:"Please fill all the fields"
        }
    }

    const found = getUserByLogin(data.get('login') as string)
    if(found){
        return {
            message:"Login is busy!"
        }
    }

    const user:OptionalUser = {
        id:nanoid(),
        name:data.get('name') as string,
        surname:data.get('surname') as string,
        login:data.get('login') as string,
    }

    user.password = await bcrypt.hash(data.get('password') as string, 10)
    redirect("/login")

}

export const handleLogin = async (prev:unknown, data:FormData) => {
    if(!data.get('login') || !data.get('password')){
        return {
            message:"please fill all the fields"
        }
    }

    let login = data.get('login') as string
    let password = data.get('password') as string

    let user = getUserByLogin(login)
    
    if(!user){
        return {
            message:"the login is incorrect!"
        }
    }
    let match = await bcrypt.compare(password, user.password)
    if(!match){
        return {
            message:"password is wrong!!"
        }
    }

    await createAuthSession(user.id)
    redirect("/profile")
}

export const handleLogout = async () => {
    await destroySession()
    redirect("/login")
}


export const handleChangeLogin = async (prev: unknown, data: FormData) => {
    if (!data.get('password') || !data.get('newlogin')) {
        return {
            message: "Please fill all the fields"
        };
    }

    const newlogin = data.get('newlogin') as string;
    const password = data.get('password') as string;

    const foundUser = await findUserByPassword(password);

    if (!foundUser) {
        return {
            message: "password is wrong!"
        };
    }

    const users = getAllUsers();
    const userWithNewLogin = users.find((u) => u.login === newlogin);

    if (userWithNewLogin) {
        return {
            message: "the login is already taken!"
        };
    }

    const new_data = { ...foundUser, login: newlogin };
    const updatedUser = updateUserInDb(new_data);
    
    if(updatedUser.changes) {
        await handleLogout();
    }
    return {
        message: "user not found!"
    };
}

async function findUserByPassword(password: string) {
    const hashedPass = await bcrypt.hash(password, 10);
    const users = await getAllUsers(); 

    for (const user of users) {
        const isMatch = await bcrypt.compare(password, user.password); 
        
        if (isMatch) {
            return user;
        }
    }
    return null; 
}
