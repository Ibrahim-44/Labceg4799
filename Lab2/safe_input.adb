with Ada.Text_IO; use Ada.Text_IO;

procedure Safe_Input is
   -- Sous-type contraint simulant un tampon de taille fixe (ex: 100 caractères)
   subtype Buffer_Type is String (1 .. 100);
   
   User_Buffer : Buffer_Type;
begin
   Put_Line("--- Test de sécurité en Ada (Exigence E7) ---");
   
   -- Simulation d'une entrée excessive (150 caractères)
   declare
      Malicious_Input : constant String := (1 .. 150 => 'A');
   begin
      Put_Line("Tentative de copie d'une chaîne de 150 caractères dans un tampon de 100...");
      User_Buffer := Malicious_Input; -- Déclenche automatiquement Constraint_Error
   end;

exception
   when Constraint_Error =>
      Put_Line("[BLOQUÉ] Erreur de contrainte interceptée (Constraint_Error) !");
      Put_Line("Aucun débordement mémoire, le programme gère l'état de façon sécurisée.");
end Safe_Input;
