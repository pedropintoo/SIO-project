## Regras

1. [DONE] Pelo menos uma role tem de ter **DOC_ACL** por documento.
2. [DONE] Em cada organização pelo menos uma role tem de ter a permissão ROLE_ACL.
3. [DONE] Sessions have a lifetime defined by the Repository, and should be deleted upon a period of inactivity
4. [DONE] Managers nunca podem ser "suspended"
5. [DONE] Managers têm de ter sempre, em qualquer altura um utilizador "active"
6. [DONE] only the first role assigned in the session have permissions in the created document

## Testes

Eliminar o ficheiro e acede-lo a partir do file_handler!

Se o servidor mudar o ficheiro e tentarmos desencriptar temos de verificar o digest. (testar isso?)
 -> Será que o rep_decrypt_file deve fazer essa verificação ou apenas o rep_get_file_doc?
 
## Perguntas 

 - mensagens de erro, suposto passar informação. SOLUÇÃO: (meter um setDefaultLevel high)
 - lifetime das sessões (5 min). SOLUÇÃO: adicionar no dicionario (DONE!)

# FALTA TESTAR!!:
 - **rep_get_doc_file** 
 - **rep_decrypt**
- **add_permission_to_document** (não é comando mas tem de ser testado!)
