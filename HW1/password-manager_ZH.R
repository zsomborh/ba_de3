library(digest)


encrypt <- function(s){
    return(digest(s, algo="sha256"))
} 


init.table <- function(){
  return(data.frame('user.name'= character(), 'password' = character() ))
}



add.or.update.user <- function(df, user.name, password){
    
    in_list = 0
    
    for( i in seq_along(df$user.name)){
        if (df$user.name[i]==user.name){
            df$password[i]<- encrypt(password)
            in_list = 1
        } 
    }
    
    if(in_list == 0){
        df <- rbind(df,list('user.name'=user.name, 'password'=encrypt(password))) 
    }
    
    return(df)
}



authenticate.user <- function (df, user.name, password){
  for(i in seq_along(df$user.name)){
      if(df$user.name[i] == user.name & df$password[i] == encrypt(password)){
          response = TRUE
          break
      } else {
          response = FALSE
      }
  }
    return(response)
}

# Example execution
user.df <- init.table()
user.df <- add.or.update.user(user.df, "example_user", "example_password")
user.df <- add.or.update.user(user.df, "example_user", "example_password_2")

# EVALUATE THE RESULTS
# These all must be TRUE
print(nrow(user.df[user.df$password == "example_password_2",]) == 0)
print(nrow(user.df[user.df$user.name == "example_user",]) == 1)
print(authenticate.user(user.df, "example_user", "example_password_2"))
print(!authenticate.user(user.df, "example_user", "example_password"))
