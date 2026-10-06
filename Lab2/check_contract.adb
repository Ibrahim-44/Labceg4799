with Ada.Text_IO; use Ada.Text_IO;

procedure Check_Contract is
   -- Définition des bornes d'index valides pour le tampon
   subtype Buffer_Range is Natural range 1 .. 100;

   -- Procédure protégée par un contrat (précondition)
   procedure Process_Safe_Input (Data : String)
     with Pre => Data'Length <= 100 -- Hypothèse formelle : longueur maximale admise
   is
   begin
      Put_Line("Entrée validée et conforme aux contrats de sécurité.");
   end Process_Safe_Input;

begin
   Put_Line("--- Test des contrats et assertions (Exigence E8) ---");
   -- Appel valide respectant la borne
   Process_Safe_Input("Donnee conforme");
end Check_Contract;
