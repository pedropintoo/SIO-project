## Regras

1. Pelo menos uma role tem de ter **DOC_ACL** por documento.
2. Em cada organização pelo menos uma role tem de ter a permissão ROLE_ACL.
3. Sessions have a lifetime defined by the Repository, and should be deleted upon a period of inactivity
4. Managers nunca podem ser "suspended"
5. Managers têm de ter sempre, em qualquer altura um utilizador "active"


## Testes

Eliminar o ficheiro e acede-lo apartir do file_handler!

Se o servidor mudar o ficheiro e tentarmos desincriptar temos de verificar o digest. (testar isso?)
 -> Será que o rep_decrypt_file deve fazer essa verificação ou apenas o rep_get_file_doc?
 
## Perguntas 

 - `-c` no subjects.py
 - docker tem problema?
 - parser da data
 - mensagens de erro, suposto passar informação. (meter um setDefaultLevel high)
 - lifetime das sessões (5 min)
 - guardar as chaves da sessão encriptadas? Elas são guardadas num dicionario, mas não são encriptadas. (não há problema porque é em memória)


# FALTA TESTAR!!:
 - **rep_get_doc_file** 
 - **rep_decrypt**

